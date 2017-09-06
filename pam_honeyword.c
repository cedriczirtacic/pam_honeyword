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
#include <string.h>
#include <unistd.h>
#include <syslog.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#define MODULE_NAME "pam_honeyword"

PAM_EXTERN int
pam_sm_authenticate(
        pam_handle_t *handler,
        int flags, int argc, const char *argv[]
    ) {
    int pam_err = PAM_SUCCESS;
    const char *username, *password;
    char *file, *rhost, *exec = NULL;
    FILE *wordlist;

    if (argc < 1){
        pam_syslog(handler, LOG_AUTH|LOG_ERR, "You must specify a wordlist.");
        return(PAM_IGNORE);
    } else {
        if (argc > 0) {
            exec = strrchr(argv[--argc], '=');
            if (exec != NULL) {
                exec++;
            } else {
                pam_syslog(handler, LOG_AUTH|LOG_ERR, "Error parsing exec= attributes");
            }
        }
    }

    if ((file = strrchr(argv[--argc], '=')) == NULL){
        pam_syslog(handler, LOG_AUTH|LOG_ERR, "Error getting wordlist file path.");
        return(PAM_IGNORE);
    } else {
        file++;
        wordlist = fopen(file, "r");
        if(wordlist == NULL){
            pam_syslog(handler, LOG_AUTH|LOG_ERR, "Error opening wordlist. (path: %s)", file);
            return(PAM_IGNORE);
        }
    }

    if ((pam_err = pam_get_user(handler, &username, NULL)) != PAM_SUCCESS)
        return(pam_err);
    
    pam_err = pam_get_authtok_noverify(handler, (const char **)&password, NULL);
    
    char p[256];
    while (fscanf(wordlist, "%s", p) != EOF) {
        if ((strcmp(p, password)) == 0) {
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

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc ,const char **argv)
{
	return(PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return(PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return(PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return(PAM_SUCCESS);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY(MODULE_NAME);
#endif

