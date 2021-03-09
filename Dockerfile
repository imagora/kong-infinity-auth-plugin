FROM kong:2.3.2-ubuntu

ADD infinity-auth /usr/local/share/lua/5.1/kong/plugins/infinity-auth
