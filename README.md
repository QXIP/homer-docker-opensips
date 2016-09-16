
![homer](http://i.imgur.com/ViXcGAD.png)

# HOMER 5 Docker
http://sipcapture.org

A simple recipe to bring up a quick, self-contained Homer5 instance:

* debian/jessie (base image)
* OpenSIPS2.2:9060 (sipcapture module)
* Apache2/PHP5:80 (homer ui/api)
* MySQL5.6/InnoDB:3306 (homer db/data)

Status: 

* [![Build Status](https://travis-ci.org/qxip/homer-docker-opensips.svg?branch=master)](https://travis-ci.org/qxip/homer-docker-opensips)

* Initial working prototype - Testing Needed!
 
## Running single container.

The single container instance is suitable for small setups and for testing only. For production, please consider using the multi-container version instead.

### Pull latest
```
docker pull qxip/homer-docker-opensips
```

### Run latest
```
docker run -tid --name homer5 -p 80:80 -p 9060:9060/udp qxip/homer-docker-opensips
```

### Running with a local MySQL

By default, the container runs with a local instance of MySQL running. It may be of interest to run MySQL with a host directory mounted as a volume for MySQL data. This will help with keeping persistent data if you need to stop & remove the running container. (Which would otherwise delete the MySQL, without a mounted volume)

You can run this container with a volume like so:

```
docker run -it -v /tmp/homer_mysql/:/var/lib/mysql --name homer5 -p 80:80 -p 9060:9060/udp qxip/homer-docker-opensips
```

### Running with an external MySQL

If you'd like to run with an external MySQL, pass in the host information for the remote MySQL as entrypoint parameters at the end of your `docker run` command.

```
docker run -tid --name homer5 -p 80:80 -p 9060:9060/udp qxip/homer-docker-opensips --dbhost 10.0.0.1 --dbuser homer_user -dbpass homer_password
```

### Entrypoint Parameters

For single-container only.

```
Homer5 Docker parameters:

    --dbpass -p             MySQL password (homer_password)
    --dbuser -u             MySQL user (homer_user)
    --dbhost -h             MySQL host (127.0.0.1 [docker0 bridge])
    --mypass -P             MySQL root local password (secret)
    --hep    -H             OpenSIPS HEP Socket port (9060)
```

### Local Build & Test
```
git clone https://github.com/qxip/homer-docker-opensips; cd homer-docker-opensips
docker build --tag="qxip/homer-docker-opensips:local" .
docker run -tid --name homer5 qxip/homer-docker-opensips:local
docker exec -it homer5 bash
```
