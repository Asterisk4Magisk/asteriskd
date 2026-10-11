// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "asteriskd.h"
#include "asteriskd_dns.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__linux__) || defined(__ANDROID__)
#include <sys/socket.h>
#include <poll.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#endif
static uint64_t get(const unsigned char *p, size_t n) {
    uint64_t v=0; for(size_t i=0;i<n;++i) v|=(uint64_t)p[i]<<(8U*i); return v;
}
static void put(unsigned char *p,uint64_t v,size_t n) {
    for(size_t i=0;i<n;++i) p[i]=(unsigned char)(v>>(8U*i));
}
void asteriskd_dns_init(struct asteriskd_dns_client *c) { memset(c,0,sizeof(*c)); c->fd=-1; }
void asteriskd_dns_close(struct asteriskd_dns_client *c) {
#if defined(__linux__) || defined(__ANDROID__)
    if(c->fd>=0) close(c->fd);
#endif
    c->fd=-1; c->connected=false; c->pending=false; free(c->tx); c->tx=NULL;
}
void asteriskd_dns_fail(struct asteriskd_dns_client *c,const char *reason) {
    asteriskd_dns_close(c); c->snapshot.phase=DNS_FAILED;
    snprintf(c->snapshot.reason,sizeof(c->snapshot.reason),"%s",reason);
}
uint64_t asteriskd_dns_boottime(void) {
#if defined(__linux__) || defined(__ANDROID__)
    struct timespec t;
    if(clock_gettime(CLOCK_BOOTTIME,&t)==0) return (uint64_t)t.tv_sec*1000U+(uint64_t)t.tv_nsec/1000000U;
#endif
    return 0;
}
static int compare_uid(const void *a,const void *b) {
    uint32_t x=*(const uint32_t *)a,y=*(const uint32_t *)b; return (x>y)-(x<y);
}
static size_t uid_array(unsigned char *out,const uint32_t *uids,size_t count) {
    uint32_t *sorted=malloc((count?count:1)*sizeof(*sorted)); if(!sorted) return SIZE_MAX;
    if(count) memcpy(sorted,uids,count*sizeof(*uids));
    qsort(sorted,count,sizeof(*sorted),compare_uid); size_t n=0;
    for(size_t i=0;i<count;++i) if(i==0 || sorted[i]!=sorted[i-1]) put(out+4*n++,sorted[i],4);
    free(sorted); return n;
}
int asteriskd_dns_command(struct asteriskd_dns_client *c,uint16_t op,
    const struct asteriskd_config *config,uint64_t now) {
    if(c->fd<0 || c->pending || c->request_id==UINT32_MAX || op<1 || op>6) return -1;
    size_t capacity=40+((op==3 || op==4)?8:0);
    if(op==2) {
        if(!config || config->uid_count>8192 || config->bypass_uid_count>8192) return -1;
        capacity+=48+4*(config->uid_count+config->bypass_uid_count);
    }
    free(c->tx); c->tx=calloc(1,capacity); if(!c->tx) return -1;
    size_t body=0;
    if(op==3 || op==4) { body=8; put(c->tx+40,now+2000,8); }
    if(op==2) {
        unsigned char *b=c->tx+40;
        uint32_t mode=config->mode==ASTERISKD_MODE_TPROXY?1:config->mode==ASTERISKD_MODE_TUN2SOCKS?2:3;
        uint32_t policy=config->app_policy_mode==ASTERISKD_APP_POLICY_GLOBAL?3:config->app_policy_mode==ASTERISKD_APP_POLICY_BLACKLIST?2:1;
        uint32_t port=mode==1?config->transparent_port:mode==2?config->helper.value.hev.socks_port:config->helper.value.bpf.socks_port;
        put(b,mode,4); put(b+4,policy,4); put(b+8,2,4); put(b+12,port,4);
        put(b+16,ASTERISKD_DNS_MARK_MASK,4); put(b+20,ASTERISKD_DNS_PROXY_DECISION,4); put(b+24,ASTERISKD_DNS_DIRECT_MARK,4);
        size_t a=uid_array(b+48,config->uids,config->uid_count);
        if(a==SIZE_MAX) return -1;
        size_t d=uid_array(b+48+4*a,config->bypass_uids,config->bypass_uid_count);
        if(d==SIZE_MAX) return -1;
        put(b+28,a,4); put(b+32,d,4); put(b+36,0,4); put(b+40,c->netd,8);
        body=48+4*(a+d); c->snapshot.phase=DNS_PREPARING; c->route_count=0;
    }
    put(c->tx,0x314e4541,4); put(c->tx+4,1,2); put(c->tx+6,op,2);
    put(c->tx+8,body,4); put(c->tx+12,++c->request_id,4);
    put(c->tx+16,c->snapshot.instance_id,8); put(c->tx+24,c->snapshot.cycle_id,8);
    put(c->tx+32,c->snapshot.generation,8);
    c->opcode=op; c->tx_size=40+body; c->tx_offset=0; c->rx_size=0;
    c->deadline=now+2000; c->pending=true; c->complete=false; c->result=0;
    if(op==3 || op==4) c->safe_after=now+5000; // Last possible publication plus full lease.
    return 0;
}
int asteriskd_dns_begin(struct asteriskd_dns_client *c,uint64_t instance,uint64_t cycle,
    uint64_t generation,uint64_t now) {
    asteriskd_dns_close(c); asteriskd_dns_init(c);
    c->snapshot=(struct asteriskd_dns_snapshot){.required=true,.phase=DNS_PREPARING,
        .instance_id=instance,.cycle_id=cycle,.generation=generation};
#if defined(__linux__) || defined(__ANDROID__)
    c->fd=socket(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    struct sockaddr_un address={.sun_family=AF_UNIX};
    const char name[]="\0asterisk.enhance.dns"; memcpy(address.sun_path,name,sizeof(name)-1);
    if(c->fd<0 || (connect(c->fd,(struct sockaddr *)&address,
        offsetof(struct sockaddr_un,sun_path)+sizeof(name)-1)!=0 && errno!=EINPROGRESS)) {
        asteriskd_dns_fail(c,"companion unavailable"); return -1;
    }
    return asteriskd_dns_command(c,1,NULL,now);
#else
    (void)now; asteriskd_dns_fail(c,"companion requires Android"); return -1;
#endif
}
int asteriskd_dns_accept(struct asteriskd_dns_client *c,const unsigned char *p,size_t n,uint64_t now) {
    if(!c->pending || now>=c->deadline || n<40 || get(p,4)!=0x314e4541 || get(p+4,2)!=1 ||
        get(p+8,4)!=n-40 || get(p+12,4)!=c->request_id ||
        get(p+16,8)!=c->snapshot.instance_id || get(p+24,8)!=c->snapshot.cycle_id ||
        get(p+32,8)!=c->snapshot.generation) goto invalid;
    if(c->opcode==1) {
        if(n!=88 || get(p+6,2)!=9) goto invalid;
        const unsigned char *b=p+40; uint32_t flags=(uint32_t)get(b+44,4);
        c->netd=get(b,8);
        if(!c->netd || get(b+8,4)!=4 || (flags&6)!=6 ||
#if !defined(ASTERISKD_DNS_TEST_PROBE) || ASTERISKD_DNS_TEST_PROBE != 1
            (flags&1) ||
#endif
            get(b+20,4)!=ASTERISKD_DNS_MARK_MASK || get(b+24,4)!=ASTERISKD_DNS_PROXY_DECISION ||
            get(b+28,4)!=ASTERISKD_DNS_DIRECT_MARK || get(b+32,4)!=2 ||
            get(b+36,4)!=3000 || get(b+40,4)!=1000) {
            asteriskd_dns_fail(c,"incompatible companion capabilities"); return -1;
        }
        c->result=(uint32_t)get(b+16,4); // Supported mode mask, checked before PREPARE.
        if(c->result==0) {
            asteriskd_dns_close(c); c->snapshot.phase=DNS_UNSUPPORTED;
            snprintf(c->snapshot.reason,sizeof(c->snapshot.reason),"module advertises no supported modes"); return -1;
        }
    } else {
        if(n<64 || (get(p+6,2)!=7 && get(p+6,2)!=8) || get(p+40,8)!=c->netd || get(p+60,4)!=0) goto invalid;
        c->result=(uint32_t)get(p+48,4); uint32_t phase=(uint32_t)get(p+52,4);
        c->retained=(uint32_t)get(p+56,4);
        if(c->opcode==2 && c->result==0 && phase==1 && get(p+6,2)==7) {
            if(n<68) goto invalid;
            size_t count=(size_t)get(p+64,4);
            if(!count || count>ASTERISKD_DNS_MAX_ROUTES || n!=68+32*count) goto invalid;
            for(size_t i=0;i<count;i++) {
                const unsigned char *b=p+68+32*i; struct asteriskd_dns_route *r=&c->routes[i];
                r->netid=(uint32_t)get(b,4);r->mark=(uint32_t)get(b+4,4);
                r->family=(uint32_t)get(b+8,4);r->scope=(uint32_t)get(b+12,4);memcpy(r->address,b+16,16);
                if(!r->netid || (r->mark&ASTERISKD_DNS_MARK_MASK) || (r->family!=4 && r->family!=6)) goto invalid;
                unsigned nonzero=0;for(size_t j=0;j<(r->family==4?4U:16U);j++)nonzero|=r->address[j];
                if(!nonzero || (r->family==4 && (r->scope || r->address[0]>=224 || r->address[0]==0)) ||
                    (r->family==6 && (r->address[0]==255 || (r->address[0]==0xfe && (r->address[1]&0xc0)==0x80 && !r->scope)))) goto invalid;
                if(r->family==4)for(size_t j=4;j<16;j++)if(r->address[j])goto invalid;
                for(size_t j=0;j<i;j++)if(!memcmp(r,&c->routes[j],sizeof(*r)))goto invalid;
            }
            c->route_count=count;
        } else if(n!=64) goto invalid;
        if(c->result==6 && c->opcode==6 && phase==3) c->snapshot.phase=DNS_DRAINING;
        else if(c->result==5 && (c->opcode==3 || c->opcode==4) && phase==3 && get(p+6,2)==8) {
            // The module has already withdrawn the old policy. Keep the
            // authenticated connection for drain and a fresh network snapshot.
            c->snapshot.phase=DNS_DRAINING; c->topology_changed=true;
        }
        else if(c->result!=0 || get(p+6,2)!=7) {
            char reason[80]; snprintf(reason,sizeof(reason),"companion command %u result %u",c->opcode,c->result);
            asteriskd_dns_fail(c,reason); return -1;
        } else if(c->opcode==2 && phase==1) c->snapshot.phase=DNS_PREPARED;
        else if((c->opcode==3 || c->opcode==4) && phase==2) {
            c->snapshot.phase=DNS_ACTIVE; c->renew_at=c->deadline-2000+1000;
            // Conservative local lease: measured from request send, never ACK receipt.
            c->lease_until=c->deadline-2000+3000;
        } else if(c->opcode==5 && (phase==0 || phase==3)) c->snapshot.phase=DNS_INACTIVE;
        else if(c->opcode==6 && phase==0 && c->retained==0) c->snapshot.phase=DNS_INACTIVE;
        else goto invalid;
    }
    c->pending=false; c->complete=true; return 0;
invalid:
    asteriskd_dns_fail(c,"late, stale or malformed companion response"); return -1;
}
int asteriskd_dns_step(struct asteriskd_dns_client *c,uint64_t now) {
    if(!c->snapshot.required || c->fd<0) return 0;
    if((c->pending && now>=c->deadline) || (c->snapshot.phase==DNS_ACTIVE && now>=c->lease_until)) {
        asteriskd_dns_fail(c,"companion command or lease expired"); return -1;
    }
#if defined(__linux__) || defined(__ANDROID__)
    if(!c->connected) {
        struct ucred peer; socklen_t n=sizeof(peer);
        if(getsockopt(c->fd,SOL_SOCKET,SO_PEERCRED,&peer,&n)!=0 || n!=sizeof(peer) || peer.uid!=0 || peer.pid<=0) {
            asteriskd_dns_fail(c,"untrusted companion peer"); return -1;
        }
        c->connected=true;
    }
    if(!c->pending && c->snapshot.phase==DNS_ACTIVE && now>=c->renew_at && !c->busy) {
        if(asteriskd_dns_command(c,4,NULL,now)!=0) return -1;
    }
    if(c->pending && c->tx_offset<c->tx_size) {
        ssize_t n=send(c->fd,c->tx+c->tx_offset,c->tx_size-c->tx_offset,MSG_DONTWAIT|MSG_NOSIGNAL);
        if(n>0) c->tx_offset+=(size_t)n;
        else if(n==0 || (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)) goto io_error;
    }
    unsigned char extra;
    if(!c->pending) {
        ssize_t n=recv(c->fd,&extra,1,MSG_DONTWAIT|MSG_PEEK);
        if(n==0 || n>0 || (n<0 && errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)) goto io_error;
        return 0;
    }
    size_t need=c->rx_size<40?40:40+(size_t)get(c->rx+8,4);
    if(need>sizeof(c->rx) || need<c->rx_size) goto io_error;
    ssize_t n=recv(c->fd,c->rx+c->rx_size,need-c->rx_size,MSG_DONTWAIT);
    if(n>0) c->rx_size+=(size_t)n;
    else if(n==0 || (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)) goto io_error;
    if(c->rx_size>=40) {
        need=40+(size_t)get(c->rx+8,4);
        if(need>sizeof(c->rx)) goto io_error;
        if(c->rx_size==need) return asteriskd_dns_accept(c,c->rx,c->rx_size,now);
    }
    return 0;
io_error:
    { char reason[128]; snprintf(reason,sizeof(reason),"companion I/O op=%u rx=%zu tx=%zu/%zu errno=%d",c->opcode,c->rx_size,c->tx_offset,c->tx_size,errno);
      asteriskd_dns_fail(c,reason); return -1; }
#else
    (void)now; return -1;
#endif
}

/* One-shot read-only bridge. No supervisor/config/log/state/network initialization. */
#if defined(__linux__) || defined(__ANDROID__)
static int info_transfer(int fd, unsigned char *bytes, size_t length, bool sending, uint64_t deadline) {
    while (length) {
        uint64_t now = asteriskd_dns_boottime();
        if (now >= deadline) return -1;
        struct pollfd event = {.fd=fd, .events=sending ? POLLOUT : POLLIN};
        int ready = poll(&event, 1, (int)(deadline - now));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) return -1;
        ssize_t count = sending ? send(fd, bytes, length, MSG_DONTWAIT | MSG_NOSIGNAL) : recv(fd, bytes, length, MSG_DONTWAIT);
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (count <= 0) return -1;
        bytes += count; length -= (size_t)count;
    }
    return asteriskd_dns_boottime() < deadline ? 0 : -1;
}
#endif
int asteriskd_dns_info(void) {
#if defined(__linux__) || defined(__ANDROID__)
    if (geteuid() != 0) { puts("AE_ROOT_DENIED"); return 0; }
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    struct sockaddr_un address = {.sun_family=AF_UNIX};
    const char name[] = "\0asterisk.enhance.dns";
    memcpy(address.sun_path, name, sizeof(name) - 1);
    bool valid = false;
    unsigned char frame[40 + 512] = {0};
    const uint64_t deadline = asteriskd_dns_boottime() + 2000;
    if (fd >= 0 && (connect(fd, (struct sockaddr *)&address,
        offsetof(struct sockaddr_un, sun_path) + sizeof(name) - 1) == 0 || errno == EINPROGRESS)) {
        struct ucred peer; socklen_t size = sizeof(peer);
        if (!getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) && size == sizeof(peer) && peer.uid == 0 && peer.pid > 1) {
            put(frame, 0x314e4541, 4); put(frame + 4, 1, 2); put(frame + 6, 10, 2); put(frame + 12, 1, 4);
            if (!info_transfer(fd, frame, 40, true, deadline) && !info_transfer(fd, frame, 40, false, deadline)) {
                size_t length = (size_t)get(frame + 8, 4);
                if (get(frame, 4) == 0x314e4541 && get(frame + 4, 2) == 1 && get(frame + 6, 2) == 11 &&
                    get(frame + 12, 4) == 1 && !get(frame + 16, 8) && !get(frame + 24, 8) && !get(frame + 32, 8) &&
                    length > 0 && length <= 512 && !info_transfer(fd, frame + 40, length, false, deadline)) {
                    valid = length >= 10 && !memcmp(frame + 40, "AE_INFO 1\n", 10) && frame[39 + length] == '\n';
                    for (size_t i = 40; valid && i < 40 + length; ++i)
                        if (frame[i] != '\n' && (frame[i] < 32 || frame[i] > 126)) valid = false;
                    if (valid) fwrite(frame + 40, 1, length, stdout);
                }
            }
        }
    }
    if (fd >= 0) close(fd);
    if (!valid) puts("AE_UNAVAILABLE");
#else
    puts("AE_UNAVAILABLE");
#endif
    return 0;
}
