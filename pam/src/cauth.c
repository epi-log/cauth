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

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

static char * global_session = NULL;
static char * global_password = NULL;

static char *
get_item (pam_handle_t * pamh, int type)
{
		char * value = NULL;
		if (pam_get_item(pamh, type, (const void **)&value) == PAM_SUCCESS && value != NULL) {
			return value;
		}
		if (type == PAM_AUTHTOK && global_password != NULL) {
			return global_password;
		}
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
	if (promptval != NULL) {
		if (type == PAM_AUTHTOK) {
			if (global_password != NULL) {
				memset(global_password, 0, strlen(global_password));
				munlock(global_password, strlen(global_password) + 1);
				free(global_password);
			}
			global_password = strdup(promptval);
			if (mlock(global_password, strlen(global_password) + 1) != 0) {
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

SSL_CTX *InitCTX(void)
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = TLSv1_2_client_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        return (NULL);
    }
	return (ctx);
}

void ShowCerts(SSL* ssl)
{
	X509 *cert;
	char *line;
 
    cert = SSL_get_peer_certificate(ssl);
    if ( cert != NULL )
    {
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        free(line);
        X509_free(cert);
    }
    else
        printf("Info: No client certificates configured.\n");
}

size_t count_digits(int number) {
	int i = 0;

	while (number > 0) {
		number = number / 10;
		i++;
	}
	return i;

}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
		FILE *f = fopen("/tmp/file.txt", "w");
        FILE *fd = fopen("/etc/pam.d/cauth.conf", "r");
        char *value = NULL;
        size_t len = 0;
        char *secret_key = NULL;
        char *message_fmt = "POST /hello_world HTTP/1.0 \r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: \r\n\r\n";
        char *message = NULL;
        size_t message_length = 0;
        char buffer[9064];
        int count = 0;
        char *username = NULL;
        char *password = NULL;
        char *ip = NULL;
        size_t username_size = 0;
        size_t password_size = 0;
        size_t ip_size = 0;
        size_t content_length = 0;
        SSL_CTX *ctx;
        int server;
        SSL *ssl;
        int sock = 0;
		unsigned long hostaddr;
		struct sockaddr_in sin;

        if (fd == NULL) {
        	fclose(fd);
        	fclose(f);
            return PAM_IGNORE;
        }
        getline(&secret_key, &len, fd);

        username_size = strlen(get_item(pamh, PAM_USER));
        if ((username = malloc(sizeof(char) * count)) == NULL) {
        	fclose(fd);
        	fclose(f);
        	free(secret_key);
         	return PAM_IGNORE;
         }
		memset(username, '\0', sizeof(username));
        strncpy(username, get_item(pamh, PAM_USER), username_size);

        password_size = strlen(get_item(pamh, PAM_AUTHTOK));
        if ((password = malloc(sizeof(char) * count)) == NULL) {
        	fclose(fd);
        	fclose(f);
        	free(secret_key);
        	free(username);
        	return PAM_IGNORE;
        }

		memset(password, '\0', sizeof(password));
        strncpy(password, get_item(pamh, PAM_AUTHTOK), password_size);

		content_length = strlen(username) + strlen(password) + strlen(&(secret_key[4])) + strlen("username=&password=&key=");
		message_length = strlen(message_fmt) + count_digits(content_length) + content_length + 1;

		if ((message = malloc(sizeof(char) * message_length)) == NULL) {
			fclose(fd);
			fclose(f);
			free(secret_key);
			free(username);
			free(password);
			return PAM_IGNORE;
		}
		memset(message, '\0', sizeof(message));
		snprintf(message, message_length, "POST /hello_world HTTP/1.0 \r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %zu\r\n\r\nusername=%s&password=%s&key=%s", content_length, username, password, &(secret_key[4]));

	    hostaddr = inet_addr("0.0.0.0");
	    sock = socket(AF_INET, SOCK_STREAM, 0);
	    sin.sin_family = AF_INET;
	    sin.sin_port = htons(443);
	    sin.sin_addr.s_addr = hostaddr;

	    if (connect(sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in)) == -1) {
            fclose(fd);
            fclose(f);
            free(secret_key);
            free(username);
            free(password);
            free(message);
            return PAM_IGNORE;
	    }
        memset(buffer, 0, sizeof(buffer));

        SSL_library_init();
        ctx = InitCTX();
        if (ctx == NULL) {
            fclose(fd);
            fclose(f);
            free(secret_key);
            free(username);
            free(password);
            free(message);
            return PAM_IGNORE;
        }
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        if (SSL_connect(ssl) == -1) {
        	ERR_print_errors_fp(f);
        	return PAM_IGNORE;
        }
        else {
			ShowCerts(ssl);
			SSL_write(ssl, message, strlen(message));
			while (SSL_read(ssl, buffer, sizeof(buffer)) != 0) {
	            if (count == 1) {
	                if (strcmp(buffer, "[\"ACCEPTED\"]") == 0) {
						free(secret_key);
						free(username);
						free(password);
						free(message);
						close(sock);
						SSL_CTX_free(ctx);
	                    fclose(fd);
	                    fclose(f);
	                    return PAM_SUCCESS;
	                }
	            }
	            memset(buffer, 0, sizeof(buffer));
	            count++;
        	}
        }
        free(secret_key);
        free(username);
        free(password);
        free(message);
		fclose(f);
		fclose(fd);
		close(sock);
		SSL_CTX_free(ctx);
		return PAM_IGNORE;
}