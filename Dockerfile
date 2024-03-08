FROM postgres

RUN sudo docker run --rm --name auth-db -e POSTGRES_PASSWORD= -e POSTGRES_USER= -e POSTGRES_DB= -d -p 5432:5432 -v $HOME/docker/volumes/postgres:/var/lib/postgresql/data postgres
