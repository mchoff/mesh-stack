# meshcore-stuff<br>
<br>

MC mesh docker stack<br><br>
- meshmonitor - MT and MC dash by Yeraze<br>
- corescope - a neat-o MC packet analyzer by KPA-Clawbot<br>
- remoteterm - a MC web client app (that can do tcp) by jkingsman<br>
- meshcore-ui - Liams web client app (doesnt do tcp - removing from stack)<br>
- caddy - for reverse proxy and ssl / w HurricaneElectric DNS-01 plugin <br>
<br>
ouside of docker stack:<br>
<br>
- pyMC_Repeater by pyMC.dev<br>
&nbsp&nbsp - pymc_modem (heltec wifi/tcp, shout out Yellowcooln rocks)<br><br>
- mqtt2mqtt proxy (migrating mqtt to pymc mqtt)<br>
&nbsp&nbsp Requires: paho-mqtt, amqtt, pynacl, passlib

<br><br><br>
All humbly running on an 8th gen i5 NUC lol<br>
work in progress...  
<br><br><br>

```
# portainer lol yep 
docker volume create portainer_data 
docker run -d -p 8000:8000 -p 9443:9443 --name portainer --restart=always -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer-ce:lts

# add the stack network first
docker network create caddy-net

# stack
git clone
mv mesh-stuff mesh 	# or whatever folder name you want 
cd mesh 
mkdir meshmonitor-data 
mkdir corescope-data 
mkdir remoteterm-data
mkdir caddy-data/data
mkdir caddy-data/config

# modify docker-compose.yaml, set any secrets or IPs.
vi docker-compose.yaml 

# modify Caddyfile with your domains/challenges
vi caddy-data/Caddyfile

# start caddy first, make sure its working (https certs)
docker compose build caddy
docker compose up -d caddy

# the rest
docker compose pull
docker compose up -d 
```
