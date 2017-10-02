/*
 * If _BAN_ is defined, the module will use libiptc and make  a simple ban
 * to the detected remote host ip.
 */
#define _BAN_
/*-
 * Copyright (c) 2017 cedriczirtacic
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by ThinkSec AS and
 * NAI Labs, the Security Research Division of Network Associates, Inc.
 * under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the
 * DARPA CHATS research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>

#ifdef _BAN_
#include <arpa/inet.h>
#include <libiptc/libiptc.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#endif

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#define MAX_BUFF 256

#define MODULE_NAME "pam_honeyword"

PAM_EXTERN int
pam_sm_authenticate(
        pam_handle_t *handler,
        int flags, int argc, const char *argv[]
    ) {
    int pam_err = PAM_SUCCESS;
    char *username, *password;
    char *file, *rhost, *exec = NULL;
    FILE *wordlist = NULL;
#ifdef _DEBUG_
            pam_syslog(handler, LOG_DEBUG, "%s PAM module started...", MODULE_NAME);
#endif

    if (argc < 1){
        pam_syslog(handler, LOG_AUTH|LOG_ERR, "You must specify a wordlist (exec is optional).");
        return(PAM_IGNORE);
    } else {
        while (argc-- > 0) {
            char param[MAX_BUFF], *p;

            unsigned int i;
            for (p = (char *)argv[argc], i = 0 ; *p != '=' && *p != '\0' && i < MAX_BUFF-1; p++, i++)
                param[i] = *p;

            param[i] = '\0';
            p++;
#ifdef _DEBUG_
            pam_syslog(handler, LOG_DEBUG, "param:%s p:%s i:%d", param, p, i);
#endif
            if (*p == 0) {
                pam_syslog(handler, LOG_AUTH|LOG_ERR, "Error parsing %s attributes", param);
                return(PAM_IGNORE);
            }

            if ((strcmp(param, "exec")) == 0) {
                exec = p;
            }
            if ((strcmp(param, "wordlist")) == 0) {
                file = p;
                wordlist = fopen(file, "r");
                if (wordlist == NULL){
                    pam_syslog(handler, LOG_AUTH|LOG_ERR, "Error opening wordlist. (path: %s)", file);
                    return(PAM_IGNORE);
                }
            }
        }
    }

    if (wordlist == NULL) {
        pam_syslog(handler, LOG_AUTH|LOG_ERR, "You must specify a wordlist (exec is optional).");
        return(PAM_IGNORE);
    }

    if ((pam_err = pam_get_user(handler, (const char **)&username, NULL)) != PAM_SUCCESS)
        return(pam_err);
    
    pam_err = pam_get_authtok_noverify(handler, (const char **)&password, NULL);
    
    char w[MAX_BUFF];
    while (fgets(w, MAX_BUFF, wordlist) != NULL) {
        w[strlen(w)-1] = '\0'; // chomp
        if ((strcmp(w, password)) == 0) {
            pam_get_item(handler, PAM_RHOST, (const void **)&rhost);
            pam_syslog(handler, LOG_AUTH|LOG_ERR, "Matching passwords (user: %s;rhost: %s).", username, rhost);
            if (exec != NULL) {
                pid_t pid;
                int status;

                pid = fork();
                if (pid == 0) {
                    // will pass both username and remote ip
                    char *eargv[] = { exec, username, rhost, NULL };
                    execve(exec, eargv, NULL);
                }
            }
#ifdef _BAN_
            if ((strchr(rhost,':')) != NULL)
                break; //no IPv6 for now...

            // ban using libiptc
            struct xtc_handle *xtch;
            struct ipt_entry *entry;
            struct ipt_entry_target *entry_target;

            const char *chain = "INPUT";
            const char *target = "DROP";
            const char *table = "filter";

            entry = calloc(1, sizeof(*entry));

            inet_aton(rhost, &entry->ip.src);
            inet_aton("255.255.255.255", &entry->ip.smsk);
            entry->ip.proto = 0; // 0 == any proto

            strcpy(entry->ip.iniface, "*");
            strcpy(entry->ip.outiface, "*");

            //setting the target
            size_t s = XT_ALIGN(sizeof( struct ipt_entry_target )) + XT_ALIGN(sizeof( int ));
            entry_target = calloc(1, s);
            entry_target->u.user.target_size = s;
            strcpy(entry_target->u.user.name, target);

            entry = realloc(entry, sizeof(*entry) + entry_target->u.target_size);
            memcpy(entry->elems, entry_target, entry_target->u.target_size);
            entry->target_offset = sizeof(*entry);
            entry->next_offset = sizeof(*entry) + entry_target->u.target_size;

            xtch = iptc_init(table);
            if (xtch == NULL) {
                pam_syslog(handler, LOG_AUTH|LOG_ERR, "Error initializing libiptc.");
                break;
            }

            if (iptc_is_chain(chain, xtch))
                if (iptc_append_entry(chain, entry, xtch))
                    pam_syslog(handler, LOG_AUTH|LOG_ERR, "%s rule applied on iptables for source %s",
                            target, rhost);
            iptc_commit(xtch);
 
            // iptc_free(xtch);
            free(entry);
            free(entry_target);
#endif
            break;
        }
    }
    fclose(wordlist);

    return(pam_err);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return(PAM_SUCCESS);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY(MODULE_NAME);
#endif

