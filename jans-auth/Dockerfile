FROM gluufederation/oxauth:4.4.1-1 AS oxauth
COPY ./ext/resources /opt/jans/jetty/jans-auth/custom/static
COPY ./lib /opt/jans/jetty/jans-auth/custom/libs/
COPY ./custom/pages /opt/jans/jetty/jans-auth/custom/pages
COPY ./scripts /opt/scripts
