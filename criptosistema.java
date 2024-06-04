
package criptosistema;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.Cipher;

/**
 *
 * @author dsanchez
 */
public class EjemploRSA {

    public static void main(String[] args) throws Exception {
        // Generar un par de claves RSA
        KeyPair parClaves = generarParClaves();

        // Obtener las claves pública y privada del par de claves
        PublicKey clavePublica = parClaves.getPublic();
        PrivateKey clavePrivada = parClaves.getPrivate();

        // Mensaje a cifrar
        String mensaje = "Buen dia, este es el mensaje";
        System.out.println("Mensaje Original: " + mensaje);
        
        // Cifrar el mensaje utilizando la clave pública
        String mensajeCifrado = cifrar(mensaje, clavePublica);
        System.out.println("Mensaje cifrado: " + mensajeCifrado);

        // Descifrar el mensaje utilizando la clave privada
        String mensajeDescifrado = descifrar(mensajeCifrado, clavePrivada);
        System.out.println("Mensaje descifrado: " + mensajeDescifrado);
    }

    // Método para generar un par de claves RSA
    public static KeyPair generarParClaves() throws Exception {
        // Inicializar el generador de pares de claves RSA con un tamaño de clave de 2048 bits
        KeyPairGenerator generadorParClaves = KeyPairGenerator.getInstance("RSA");
        generadorParClaves.initialize(2048);
        
        // Generar el par de claves
        return generadorParClaves.generateKeyPair();
    }

    // Método para cifrar un mensaje utilizando la clave pública
    public static String cifrar(String mensaje, PublicKey clavePublica) throws Exception {
        // Obtener una instancia de Cipher para RSA
        Cipher cifrador = Cipher.getInstance("RSA");
        
        // Inicializar el cifrador en modo de cifrado con la clave pública
        cifrador.init(Cipher.ENCRYPT_MODE, clavePublica);
        
        // Cifrar el mensaje y convertir el resultado a una representación en base64
        byte[] bytesCifrados = cifrador.doFinal(mensaje.getBytes());
        return Base64.getEncoder().encodeToString(bytesCifrados);
    }

    // Método para descifrar un mensaje utilizando la clave privada
    public static String descifrar(String mensajeCifrado, PrivateKey clavePrivada) throws Exception {
        // Decodificar el mensaje cifrado de base64
        byte[] bytesCifrados = Base64.getDecoder().decode(mensajeCifrado);
        
        // Obtener una instancia de Cipher para RSA
        Cipher cifrador = Cipher.getInstance("RSA");
        
        // Inicializar el cifrador en modo de descifrado con la clave privada
        cifrador.init(Cipher.DECRYPT_MODE, clavePrivada);
        
        // Descifrar el mensaje
        byte[] bytesDescifrados = cifrador.doFinal(bytesCifrados);
        
        // Convertir los bytes descifrados de nuevo a una cadena de texto
        return new String(bytesDescifrados);
    }
}
