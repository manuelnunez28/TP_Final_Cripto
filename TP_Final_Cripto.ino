#pragma GCC diagnostic ignored "-fpermissive"
#pragma GCC diagnostic ignored "-pedantic"

#include "max6675.h"
#include <WiFi.h>
#include <PubSubClient.h>
#include "core.h"
#include "api.h"
#include "permutations.h"
#include "bendian.h"
#include <string.h>

#define CRYPTO_BYTES 64

int thermoDO = 4;
int thermoCS = 5;
int thermoCLK = 6;

unsigned char stemp[10];
unsigned char celcius[5] = " °C";
float temp;

// WiFi 
//const unsigned char *ssid = "Fibertel WiFi367 2.4GHz"; // Nombre WiFi
//const unsigned char *password = "0141200866";  // Contraseña del WiFi

const unsigned char *ssid = "Moto G (5) Plus 6864";
const unsigned char *password = "manuel123";

// MQTT Broker
//const unsigned char *mqtt_broker = "192.168.0.248";
const unsigned char *mqtt_broker = "192.168.255.99";
const unsigned char *topic = "mosquitto/esp32";
//const unsigned char *mqtt_username = "";
//const unsigned char *mqtt_password = "";
const int mqtt_port = 1883;

WiFiClient espClient;
PubSubClient client(espClient);

MAX6675 thermocouple(thermoCLK, thermoCS, thermoDO);

unsigned long long clen;

unsigned char cipher[CRYPTO_BYTES]; 
unsigned char npub[CRYPTO_NPUBBYTES]="";
unsigned char ad[CRYPTO_ABYTES]="";
unsigned char nsec[CRYPTO_ABYTES]="";

const unsigned char ad2[CRYPTO_ABYTES]="";

unsigned char key[CRYPTO_KEYBYTES];


unsigned char keyhex[2*CRYPTO_KEYBYTES+1]="0123456789ABCDEF0123456789ABCDEF";
unsigned char nonce[2*CRYPTO_NPUBBYTES+1]="000000000000111111111111";

void setup() {

    // Se setea el baudrate a 9600;
    Serial.begin(9600);    
  
    Serial.println("MAX6675 test");
    // espera a que el MAX6675 se estabilice
    delay(500);

    // Conexion con la red WiFi
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.println("Connecting to WiFi network..");
    }
    
    Serial.println("Connected to WiFi network");
    // Conexión con el broker MQTT
    client.setServer(mqtt_broker, mqtt_port);
    client.setCallback(callback);
    
    while (!client.connected()) {
        String client_id = "esp32-client-";
        client_id += String(WiFi.macAddress());
        Serial.printf("The client %s is connecting to broker MQTT\n", client_id.c_str());
        if (client.connect(client_id.c_str())) {
            Serial.println("Broker Mosquitto MQTT connected");
        } else {
            Serial.print("failed with state ");
            Serial.print(client.state());
            delay(2000);
        }
    }
    
    // Publicación y suscripción
    client.subscribe(topic);

}

void loop() {
  //Se guarda la temperatura en grados celsius
  temp = thermocouple.readCelsius();
  
  dtostrf(temp, 4, 2, stemp); //Convierte el float a una cadena
  
  strcat(stemp, celcius);

  
  int ret = crypto_aead_encrypt(cipher,&clen,stemp,strlen(stemp),ad,strlen(ad2),nsec,nonce,keyhex);
  Serial.print(ret);
  
  client.publish(topic, stemp);
  client.loop();
  
  // Para que se actualicen los datos del MAX6675 se necesita un delay minimo de 250ms
  delay(1000);
}


void callback(unsigned char *topic, byte *payload, unsigned int length) {
    Serial.print("Message arrived in topic: ");
    Serial.println(topic);
    Serial.print("Message:");
    for (int i = 0; i < length; i++) {
        Serial.print((unsigned char) payload[i]);
    }
    Serial.println();
    Serial.println("-----------------------");
}

int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        unsigned char* m, unsigned long long mlen,
                        unsigned char* ad, unsigned long long adlen,
                        unsigned char* nsec, unsigned char* npub,
                        unsigned char* k) {
  state s;
  u32_4 tmp;
  (void)nsec;

  // set ciphertext size
  *clen = mlen + CRYPTO_ABYTES;

  ascon_core(&s, c, m, mlen, ad, adlen, npub, k, ASCON_ENC);

  tmp.words[0] = s.x3;
  tmp.words[1] = s.x4;
  tmp = ascon_rev8(tmp);

  // set tag
  ((u32*)(c + mlen))[0] = tmp.words[0].h;
  ((u32*)(c + mlen))[1] = tmp.words[0].l;
  ((u32*)(c + mlen))[2] = tmp.words[1].h;
  ((u32*)(c + mlen))[3] = tmp.words[1].l;

  return 0;
}
