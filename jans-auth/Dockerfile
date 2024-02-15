FROM ghcr.io/janssenproject/jans/auth-server:1.0.22_dev AS auth-server
COPY ./ext/resources /opt/jans/jetty/jans-auth/custom/static
COPY ./lib /opt/jans/jetty/jans-auth/custom/libs
COPY ./custom/pages /opt/jans/jetty/jans-auth/custom/pages
COPY ./scripts /opt/jans/jetty/jans-auth/custom/scripts
