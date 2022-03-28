#=======================#
# composer já instalado #
#=======================#
FROM adrianowead/viware-base-php:1.1.0

RUN usermod -a -G sudo www-data

RUN chmod -R 775 /var/www/html

# ajustando permissão da pasta para o apache
# e habilitando alguns módulos
RUN chown -R www-data:www-data /var/www/html

# abrindo portas
EXPOSE 80

# iniciando supervisor
ENTRYPOINT ["supervisord"]
