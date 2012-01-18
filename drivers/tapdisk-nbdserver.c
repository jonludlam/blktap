#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>

#include "tapdisk.h"
#include "tapdisk-server.h"
#include "tapdisk-driver.h"
#include "tapdisk-interface.h"
#include "tapdisk-utils.h"
#include "tapdisk-nbdserver.h"

#include "nbd.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define NBD_SERVER_NUM_REQS 10

/*
 * Server 
 */

#define INFO(_f, _a...)            tlog_syslog(TLOG_INFO, "nbd: " _f, ##_a)
#define ERROR(_f, _a...)           tlog_syslog(TLOG_WARN, "nbd: " _f, ##_a)

struct td_nbdserver_req {
	td_vbd_request_t        vreq;
	char                    id[8];
};

td_nbdserver_req_t *
tapdisk_nbdserver_alloc_request(td_nbdserver_client_t *client)
{
	td_nbdserver_req_t *req = NULL;

	if (likely(client->n_reqs_free))
		req = client->reqs_free[--client->n_reqs_free];

	return req;
}

void
tapdisk_nbdserver_free_request(td_nbdserver_client_t *client, td_nbdserver_req_t *req)
{
	BUG_ON(client->n_reqs_free >= client->n_reqs);
	client->reqs_free[client->n_reqs_free++] = req;
}

static void
tapdisk_nbdserver_reqs_free(td_nbdserver_client_t *client)
{
	if (client->reqs) {
		free(client->reqs);
		client->reqs = NULL;
	}

	if (client->iovecs) {
		free(client->iovecs);
		client->iovecs = NULL;
	}

	if (client->reqs_free) {
		free(client->reqs_free);
		client->reqs_free = NULL;
	}
}

static int
tapdisk_nbdserver_reqs_init(td_nbdserver_client_t *client, int n_reqs)
{
	int i, err;

	client->reqs = malloc(n_reqs * sizeof(td_nbdserver_req_t));
	if (!client->reqs) {
		err = -errno;
		goto fail;
	}
	client->iovecs = malloc(n_reqs * sizeof(struct td_iovec));
	if (!client->iovecs) {
		err = - errno;
		goto fail;
	}

	client->reqs_free = malloc(n_reqs * sizeof(td_nbdserver_req_t*));
	if (!client->reqs_free) {
		err = -errno;
		goto fail;
	}

	client->n_reqs      = n_reqs;
	client->n_reqs_free = 0;

	for (i = 0; i < n_reqs; i++) {
		client->reqs[i].vreq.iov=&client->iovecs[i];
		tapdisk_nbdserver_free_request(client, &client->reqs[i]);
	}

	return 0;

fail:
	tapdisk_nbdserver_reqs_free(client);
	return err;
}

static td_nbdserver_client_t *
tapdisk_nbdserver_alloc_client(td_nbdserver_t *server)
{
	td_nbdserver_client_t *client=NULL;
	int err;

	client=malloc(sizeof(td_nbdserver_client_t));
	if(!client) {
		ERROR("Couldn't allocate client structure: %s",strerror(errno));
		goto fail;
	}

	err = tapdisk_nbdserver_reqs_init(client, NBD_SERVER_NUM_REQS);
	if(err<0) {
		ERROR("Couldn't allocate client reqs: %d",err);
		goto fail;
	}

	client->client_fd=-1;
	client->client_event_id=-1;
	INIT_LIST_HEAD(&client->clientlist);
	list_add(&client->clientlist, &server->clients);

 fail:
	if(client) {
		free(client);
		client=NULL;
	}

	return client;
}

static void
tapdisk_nbdserver_free_client(td_nbdserver_client_t *client)
{
	if(!client) {
		ERROR("Attempt to free NULL pointer!");
		return;
	}

	if(client->client_event_id >= 0) {
		tapdisk_nbdserver_disable_client(client);
	}

	if(client->client_fd >= 0) {
		close(client->client_fd);
	}

	list_del(client->clientlist);
	tapdisk_nbdserver_reqs_free(client);
	free(client);
}

static int 
tapdisk_nbdserver_enable_client(td_nbdserver_client_t *client)
{
	if(client->client_event_id >= 0) {
		ERROR("Attempting to enable an already-enabled client");
		return -1;
	}

	if(client->client_fd < 0) {
		ERROR("Attempting to register events on a closed client");
		return -1;
	}

	client->client_event_id =
		tapdisk_server_register_event(SCHEDULER_POLL_READ_FD,
									  client->client_fd, 0,
									  tapdisk_nbdserver_clientcb,
									  client);	

	if(client->client_event_id < 0) {
		ERROR("Error registering events on client: %d",client->client_event_id);
		return client->client_event_id;
	}
}

static void
tapdisk_nbdserver_disable_client(td_nbdserver_client_t *client)
{
	if(client->client_event_id < 0) {
		ERROR("Attempting to disable an already-disabled client");
		return;
	}
	
	tapdisk_server_unregester_event(client->client_event_id);
	client->client_event_id=-1;
}

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}




static void
tapdisk_nbdserver_clientcb(event_id_t id, char mode, void *data)
{
  td_nbdserver_client_t *client=data;
  int rc;
  int len;

  /* not good enough */
  td_nbdserver_req_t *req=tapdisk_nbdserver_alloc_request(client);
  td_vbd_request_t *vreq=req->vreq;

  if(req==NULL) {
	  ERROR("Couldn't allocate request in clientcb - killing client");
	  tapdisk_nbdserver_free_client(client);
	  return;
  }

  memset(req, 0, sizeof(td_nbdserver_req_t))
  /* Read the request the client has sent */
  rc=recv(server->client_fd, &request, sizeof(nbd_request), 0);
  
  if(rc<sizeof(nbd_request)) {
	ERROR("Short read in nbdserver_clientcb. Closing connection");
	goto fail;
  }

  if(request.magic != htonl(NBD_REQUEST_MAGIC)) {
	ERROR("Not enough magic");
	goto fail;
  }

  request.from = ntohll(request.from);
  request.type = ntohl(request.type);
  len = ntohl(request.len);
  if((len && 0x1ff != 0) || (request.from && 0x1ff != 0)) {
	ERROR("Non sector-aligned request");
  }

  switch(request.type) {
  case NBD_CMD_READ:
	  vreq.op=TD_OP_READ;
	  vreq.sec=request.from >> SECTOR_SHIFT;
	  vreq.iovcnt=1;
	  vreq.iov->base = malloc(len);
	  vreq.iov->secs = len >> SECTOR_SHIFT;
	  vreq.token = client;
	  vreq.cb = __tapdisk_nbdserver_request_cb;

	  tapdisk_blktap_vector_request
  }

 fail:

  tapdisk_nbdserver_free_client(client);
  return;
}

static void
tapdisk_nbdserver_newclient(event_id_t id, char mode, void *data)
{
  struct sockaddr_storage their_addr;
  socklen_t sin_size = sizeof(their_addr);
  char s[INET6_ADDRSTRLEN];
  int new_fd;
  td_nbdserver_t *server=data;
  td_vbd_t = server->vbd;
  

  char buffer[256];
  int rc;
  uint64_t tmp;
  uint32_t tmp32;

  INFO("About to accept (server->listening_fd=%d)",server->listening_fd);
  new_fd = accept(server->listening_fd, (struct sockaddr *)&their_addr, &sin_size);
  if (new_fd == -1) {
	
	ERROR("accept (%s)", strerror(errno));
	return;
  }

  INFO("Got a new client!");

  inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);

  INFO("server: got connection from %s\n", s);

  /* Spit out the NBD connection stuff */

  memcpy(buffer, "NBDMAGIC", 8);
  tmp=ntohll(NBD_NEGOTIATION_MAGIC);
  memcpy(buffer+8, &tmp, sizeof(tmp));
  tmp=ntohll(server->info.size * server->info.sector_size);
  memcpy(buffer+16, &tmp, sizeof(tmp));
  tmp32=ntohl(0);
  memcpy(buffer+24, &tmp32, sizeof(tmp32));
  bzero(buffer+28, 124);
  
  rc=send(new_fd, buffer, 152, 0);

  if(rc<152) {
	close(new_fd);
	INFO("Short write in negotiation!");
  }	

  td_nbdserver_client_t *client=tapdisk_nbdserver_alloc_client(server);
  client->client_fd = new_fd;

  if(tapdisk_nbdserver_enable_client(client) < 0) {
	  ERROR("Error enabling client");
	  tapdisk_nbdserver_free_client(client);
	  close(new_fd);
	  return;
  }

}

int
tapdisk_nbdserver_open(td_vbd_t *vbd, td_disk_info_t *info)
{
	td_nbdserver_t *server;
	struct addrinfo hints, *servinfo, *p;

	int err;
	int yes=1;

	server = malloc(sizeof(*server));
	if (!server) {
		err = -errno;
		goto fail;
	}

	memset(server, 0, sizeof(*server));
	server->listening_fd = -1;
	server->listening_event_id = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if ((err=getaddrinfo(NULL, "2000", &hints, &servinfo)) != 0) {
	  ERROR("Failed to getaddrinfo");
	  return -1;
	}

	for(p=servinfo; p != NULL; p = p->ai_next) {
	  if((server->listening_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		ERROR("Failed to create socket");
		continue;
	  }

	  if(setsockopt(server->listening_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		ERROR("Failed to setsockopt");
		close(server->listening_fd);
		return -1;
	  }
		
	  if(bind(server->listening_fd, p->ai_addr, p->ai_addrlen) == -1) {
		ERROR("Failed to bind");
		close(server->listening_fd);
		continue;
	  }

	  break;
	}

	if(p==NULL) {
	  ERROR("Failed to bind");
	  close(server->listening_fd);
	  return -1;
	}

	freeaddrinfo(servinfo);

	if(listen(server->listening_fd, 10) == -1) {
	  ERROR("listen");
	  return -1;
	}

	server->vbd = vbd;
	server->info = *info;

	server->listening_event_id =
		tapdisk_server_register_event(SCHEDULER_POLL_READ_FD,
					      server->listening_fd, 0,
					      tapdisk_nbdserver_newclient,
					      server);

	if (server->listening_event_id < 0) {
		err = server->listening_event_id;
		close(server->listening_fd);
	}

	INFO("Successfully started NBD server");

	return 0;

fail:
	return err;
}

