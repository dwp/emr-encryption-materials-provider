package uk.gov.dwp.dataworks.encryptionmaterialsprovider;

/**
 *
 * @author jasonedge
 */
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import org.apache.commons.io.IOUtils;
import org.apache.hadoop.conf.Configurable;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
//import org.apache.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyFactory;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.LocalDateTime;
import java.util.UUID;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

/**
 * Provides encryption materials using rsa key pair stored in s3
 */
public class DWEncryptionMaterialsProvider implements EncryptionMaterialsProvider, Configurable {
    private static final Logger logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);

    private final String RSA = "RSA";
    private final String CSE_RSA_NAME = "rsa_name";
    private final String CSE_RSA_NAME_CONF = "fs.s3.cse.rsa.name";
    private final String CSE_ENCR_KEYPAIRS_BUCKET = "fs.s3.cse.encr.keypairs.bucket";
    private final String CSE_RSA_PUBLIC_CONF = "fs.s3.cse.rsa.public";
    private final String CSE_RSA_PRIVATE_CONF = "fs.s3.cse.rsa.private";

    private AmazonS3 s3;
    private Configuration conf;
    private EncryptionMaterials encryptionMaterials;
    private String strDescriptionValue;
    private String strEncryptionKeypairsBucket;
    private Gson gson;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private KeyPair kpCurrentSubsidiary;
    private String strKpCurrentSubsidiaryFilename;
    private LocalDateTime datetimeKpCurrentSubsidiaryExpiryTime;
    private Base64.Encoder b64Encoder;
    private Base64.Decoder b64Decoder;
    private HashMap<String, KeyPair> mapDecryptionKPs;
    private LocalDateTime datetimeDecryptionKPsExpiryTime;

    private void init() {

        logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->init() Conf2: " + this.conf.toString());

        try {

            this.b64Encoder = Base64.getEncoder();
            this.b64Decoder = Base64.getDecoder();
            this.gson = new GsonBuilder()
                    .serializeSpecialFloatingPointValues()
                    .serializeNulls()
                    .create();
            logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->init() gson initialised");

            this.strDescriptionValue = this.conf.get(CSE_RSA_NAME_CONF);
            this.strEncryptionKeypairsBucket = this.conf.get(CSE_ENCR_KEYPAIRS_BUCKET);
            Preconditions.checkArgument(!Strings.isNullOrEmpty(this.strDescriptionValue), String.format("%s cannot be empty", CSE_RSA_NAME_CONF));
            Preconditions.checkArgument(!Strings.isNullOrEmpty(this.strEncryptionKeypairsBucket), String.format("%s cannot be empty", CSE_ENCR_KEYPAIRS_BUCKET));
            logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->init() preconditions checked");

            URI uriPublicKey = new URI(this.conf.get(CSE_RSA_PUBLIC_CONF));
            URI uriPrivateKey = new URI(this.conf.get(CSE_RSA_PRIVATE_CONF));

            setupClearKeypairCache();

            InputStream publicKeyIS, privateKeyIS;

            //* see 'NOTE-1' above
            if ("s3".equalsIgnoreCase(uriPublicKey.getScheme()) || "s3n".equalsIgnoreCase(uriPublicKey.getScheme())) {
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->init() s3 or S3n scheme for public key");

                initializeAmazonS3(); //* see 'NOTE-1' above
                String publicKeyS3Bucket = getBucket(uriPublicKey);
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->init() publicKeyS3Bucket: " + publicKeyS3Bucket);

                String publicKeyS3Key = getKey(uriPublicKey);
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->init() publicKeyS3Key: " + publicKeyS3Key);

                publicKeyIS = s3.getObject(publicKeyS3Bucket, publicKeyS3Key).getObjectContent();
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->init() publicKeyIS: " + publicKeyIS.toString());
            } else {
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->init() no s3 or S3n scheme for public key");

                Path publicKeyPath = new Path(uriPublicKey);
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->init() publicKeyPath: " + publicKeyPath.toString());

                FileSystem fs = publicKeyPath.getFileSystem(conf);
                publicKeyIS = fs.open(publicKeyPath);
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->init() publicKeyIS: " + publicKeyIS.toString());
            }

            //* see 'NOTE-1' above
            if ("s3".equalsIgnoreCase(uriPrivateKey.getScheme()) || "s3n".equalsIgnoreCase(uriPrivateKey.getScheme())) {
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->init() s3 or S3n scheme for private key");

                initializeAmazonS3(); //* see 'NOTE-1' above
                String privateKeyS3Bucket = getBucket(uriPrivateKey);
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->init() privateKeyS3Bucket: " + privateKeyS3Bucket);

                String privateKeyS3Key = getKey(uriPrivateKey);
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->init() privateKeyS3Key: " + privateKeyS3Key);

                privateKeyIS = s3.getObject(privateKeyS3Bucket, privateKeyS3Key).getObjectContent();
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->init() privateKeyIS: " + privateKeyIS.toString());
            } else {
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->init() no s3 or S3n scheme for private key");

                Path privateKeyPath = new Path(uriPrivateKey);
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->init() privateKeyPath: " + privateKeyPath.toString());

                FileSystem fs = privateKeyPath.getFileSystem(conf);
                privateKeyIS = fs.open(privateKeyPath);
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->init() privateKeyIS: " + privateKeyIS.toString());
            }

            this.publicKey = getRSAPublicKey(publicKeyIS);
            logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->init() publicKey: " + this.publicKey.toString());

            this.privateKey = getRSAPrivateKey(privateKeyIS);
            logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->init() privateKey: " + this.privateKey.toString());

        } catch (URISyntaxException | IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.log(Level.SEVERE, "[DWEncryptionMaterialsProvider]->init() Exception: " + e);

            throw new RuntimeException(e);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "[DWEncryptionMaterialsProvider]->init() General Exception: " + e);

            throw new RuntimeException(e);
        }
    }

    //* NOTE-1: The following method is not required once the HSM and DKS are available - in the interim it is used to host a
    //* PPK as a proxy for that managed by the HSM
    private void initializeAmazonS3() {
        logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->initializeAmazonS3()");

        if (s3 == null) {
            logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->initializeAmazonS3(): s3 is null");

            try {
                s3 = AmazonS3ClientBuilder.standard()
                        .withRegion(Regions.EU_WEST_2)
                        .build();

                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->initializeAmazonS3(): s3 is defaultClient()" + s3.toString());
            } catch (Exception e) {
                logger.log(Level.SEVERE, "[DWEncryptionMaterialsProvider]->initializeAmazonS3(): Exception:" + e);
                throw new RuntimeException(e);
            }
        }
    }

    private void setupClearKeypairCache() {
        logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->setupClearKeypairCache()");

        this.mapDecryptionKPs = new HashMap<String, KeyPair>();
        this.datetimeDecryptionKPsExpiryTime = LocalDateTime.now().plusHours(24);
    }

    @Override
    public EncryptionMaterials getEncryptionMaterials(Map<String, String> materialsDescription) {

        try {
            logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->getEncryptionMaterials(Map)");

            if (materialsDescription != null) {
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->getEncryptionMaterials(Map) materialsDescription != null ");

                for (Map.Entry<String, String> entry : materialsDescription.entrySet()) {
                    logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->getEncryptionMaterials(Map): Key = " + entry.getKey() + ", Value = " + entry.getValue());
                }

                String mode = materialsDescription.getOrDefault("mode", "");
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->getEncryptionMaterials(Map): decryption mode = '" + mode + "'");

                if (mode.equals("double")) {
                    return determineDoubleEncryptionMaterials(materialsDescription);

                } else {

                    if (mode.equals("doubleReuse")) {
                        return determineDoubleReuseEncryptionMaterials(materialsDescription);

                    } else { // no mode provided, indicating a request to encrypt
                        return determineDoubleEncryptionMaterialsForEncrypt();
                    }
                }
            }

        } catch (Exception e) {
            logger.log(Level.SEVERE, "[DWEncryptionMaterialsProvider]->getEncryptionMaterials(Map) General Exception: " + e);

            throw new RuntimeException(e);
        }

        return this.encryptionMaterials;
    }

    @Override
    public EncryptionMaterials getEncryptionMaterials() {
        try {
            logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->getEncryptionMaterials()");

            if (this.encryptionMaterials != null) {
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->getEncryptionMaterials(): this.materialsDescription is not null:" + this.encryptionMaterials.toString());

                try {
                    logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->getEncryptionMaterials(): this.encryptionMaterials JSON = " + this.gson.toJson(this.encryptionMaterials));
                } catch (Exception e) {
                    logger.log(Level.SEVERE, "[DWEncryptionMaterialsProvider]->getEncryptionMaterials() Gson Exception: " + e);
                    e.printStackTrace();
                }

                return this.encryptionMaterials;
            } else {
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->getEncryptionMaterials() Exception: RSA key pair is not initialized.");

                throw new RuntimeException("RSA key pair is not initialized.");
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "[DWEncryptionMaterialsProvider]->getEncryptionMaterials() General Exception: " + e);

            throw new RuntimeException(e);
        }
    }

    @Override
    public void refresh() {
        logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->refresh()");

    }

    @Override
    public Configuration getConf() {
        logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->getConf()");

        return this.conf;
    }

    @Override
    public void setConf(Configuration conf) {
        logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->setConf()");

        this.conf = conf;
        init();
    }

    private PrivateKey getRSAPrivateKey(InputStream isPrivateKey)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->getRSAPrivateKey(InputStream)");

        byte[] privateKeyBytes = IOUtils.toByteArray(isPrivateKey);
        return getRSAPrivateKey(privateKeyBytes);
    }

    private PrivateKey getRSAPrivateKey(byte[] bytesPrivateKey)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->getRSAPrivateKey(byte[])");

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytesPrivateKey);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        return keyFactory.generatePrivate(spec);
    }

    private PublicKey getRSAPublicKey(InputStream isPublicKey)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->getRSAPublicKey(InputStream)");

        byte[] bytesPublicKey = IOUtils.toByteArray(isPublicKey);
        return getRSAPublicKey(bytesPublicKey);
    }

    private PublicKey getRSAPublicKey(byte[] bytesPublicKey)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->getRSAPublicKey(byte[])");

        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytesPublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        return keyFactory.generatePublic(spec);
    }

    private String getBucket(URI s3Uri) throws URISyntaxException {
        logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->getBucket(): s3Uri: " + s3Uri.toString());

        return s3Uri.getHost();
    }

    private String getKey(URI s3Uri) throws URISyntaxException {
        logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->getKey(): s3Uri: " + s3Uri.toString());

        return s3Uri.getPath().substring(1);
    }

    private EncryptionMaterials determineDoubleEncryptionMaterials(Map<String, String> materialsDescription) {
        logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleEncryptionMaterials()");

        try {

            String b64EEM = materialsDescription.getOrDefault("eem", "");
            logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleEncryptionMaterials() b64EEM = " + b64EEM);

            String b64EEMKey = materialsDescription.getOrDefault("eemkey", "");
            logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleEncryptionMaterials() b64EEMKey = " + b64EEMKey);

            String b64EEMKeyIV = materialsDescription.getOrDefault("eemkeyiv", "");
            logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleEncryptionMaterials() b64EEMKeyIV = " + b64EEMKeyIV);

            if (b64EEM != "" && b64EEMKey != "" && b64EEMKeyIV != "") {
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleEncryptionMaterials() encryption material description successfully received");

                // decrypt second sym using private key from DKS/HSM PK
                byte[] bytesEEMKey = decryptWithDKS(b64EEMKey);
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleEncryptionMaterials() EEMKey = " + new String(bytesEEMKey));

                // extract EEM from Base64-encoded string
                byte[] bytesEEM = this.b64Decoder.decode(b64EEM);
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleEncryptionMaterials() EEM = " + new String(bytesEEM));

                // extract EEMKeyIV from Base64-encoded string
                byte[] bytesEEMKeyIV = this.b64Decoder.decode(b64EEMKeyIV);
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleEncryptionMaterials() b64EEMKeyIV = " + new String(bytesEEMKeyIV));

                // decrypt second sym (envSymKey2) itself - yielding KeyPair to pass back as encrption Materials
                SecretKey envSymKey2 = new SecretKeySpec(bytesEEMKey, "AES");
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleEncryptionMaterials() got envSymKey2 = " + envSymKey2.toString());

                Cipher cipherEnvSymKey2 = Cipher.getInstance("AES/GCM/NoPadding");
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleEncryptionMaterials() got cipher2 instance = " + cipherEnvSymKey2.toString());

                cipherEnvSymKey2.init(Cipher.DECRYPT_MODE, envSymKey2, new IvParameterSpec(bytesEEMKeyIV));
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleEncryptionMaterials() initialised cipher2");

                byte[] bytesEnvKP = cipherEnvSymKey2.doFinal(bytesEEM);
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleEncryptionMaterials() bytesEnvKP = " + new String(bytesEnvKP));

                KeyPair skKP = new KeyPair(null, getRSAPrivateKey(bytesEnvKP));
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleEncryptionMaterials() skKP: " + skKP.toString());

                EncryptionMaterials localEncryptionMaterials = new EncryptionMaterials(skKP);
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleEncryptionMaterials() localEncryptionMaterials: " + localEncryptionMaterials.toString());

                localEncryptionMaterials.addDescription(CSE_RSA_NAME, strDescriptionValue);
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleEncryptionMaterials() localEncryptionMaterials - adding description: " + CSE_RSA_NAME + ", " + strDescriptionValue);

                return localEncryptionMaterials;

            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "[DWEncryptionMaterialsProvider]->determineDoubleEncryptionMaterials() General Exception: " + e);

            throw new RuntimeException(e);
        }

        return this.encryptionMaterials;
    }

    private EncryptionMaterials determineDoubleReuseEncryptionMaterials(Map<String, String> materialsDescription) {
        logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleReuseEncryptionMaterials()");

        KeyPair kpDecryption;

        String kpKeyId = materialsDescription.getOrDefault("keyid", "fdf11ee8-644d-4c2e-a9de-698af670a618");
        logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleReuseEncryptionMaterials() kpKeyId = " + kpKeyId);

        try {
            // if the local cache of keypairs has expired, clear it now
            if (LocalDateTime.now().isAfter(this.datetimeDecryptionKPsExpiryTime)) {
                setupClearKeypairCache();
            }

            // if the local keypair cache contains this keypair - use it, otherwise load it and add it to the cache
            if (this.mapDecryptionKPs.containsKey(kpKeyId)) {
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleReuseEncryptionMaterials() Fetching keypair from cache. kpKeyId: " + kpKeyId);
                kpDecryption = this.mapDecryptionKPs.get(kpKeyId);
            } else {
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleReuseEncryptionMaterials() Keypair is not in cache. Fetching from keystore. kpKeyId: " + kpKeyId);

                InputStream isKpSubsidiary = s3.getObject(this.strEncryptionKeypairsBucket, kpKeyId).getObjectContent();
                String strJsonKpSubsidiary = IOUtils.toString(isKpSubsidiary);
                Map<String, String> mapKpSubsidiary = new Gson().fromJson(strJsonKpSubsidiary, new TypeToken<HashMap<String, String>>() {
                }.getType());

                byte[] bytesSymEncryptedKpPriv = mapKpSubsidiary.get("priv").getBytes();
                String strSymkeyIV = mapKpSubsidiary.get("symkeyiv");
                String strDKSEncryptedSymkey = mapKpSubsidiary.get("symkey");

                // decrypt private half of subsidiary keypair using symkey

                //***
                // decrypt symmetric key using DKS
                byte[] bytesSymKey = decryptWithDKS(strDKSEncryptedSymkey);
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleReuseEncryptionMaterials() decrypted bytesSymKey using DKS");

                // extract SymKeyIV from Base64-encoded string
                byte[] bytesSymKeyIV = this.b64Decoder.decode(strSymkeyIV);
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleReuseEncryptionMaterials() extracted bytesSymKeyIV from Base64-encoded string");

                // use the symkey to decrypt the private half of the keypair - yielding KeyPair to pass back as encryption Materials
                SecretKey skSymKey = new SecretKeySpec(bytesSymKey, "AES");
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleReuseEncryptionMaterials() got skSymKey");

                Cipher cipherSymKey = Cipher.getInstance("AES/GCM/NoPadding");
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleReuseEncryptionMaterials() got cipherSymKey");

                cipherSymKey.init(Cipher.DECRYPT_MODE, skSymKey, new IvParameterSpec(bytesSymKeyIV));
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleReuseEncryptionMaterials() initialised cipherSymKey");

                byte[] bytesKpPriv = cipherSymKey.doFinal(this.b64Decoder.decode(bytesSymEncryptedKpPriv));
                logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleReuseEncryptionMaterials() decrypted KpPriv");

                //***
                kpDecryption = new KeyPair(null, getRSAPrivateKey(bytesKpPriv));
                this.mapDecryptionKPs.put(kpKeyId, kpDecryption);
            }

            EncryptionMaterials localEncryptionMaterials = new EncryptionMaterials(kpDecryption);
            localEncryptionMaterials.addDescription("mode", "doubleReuse");
            logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleReuseEncryptionMaterials() created localEncryptionMaterials");

            return localEncryptionMaterials;

        } catch (Exception e) {
            logger.log(Level.SEVERE, "[DWEncryptionMaterialsProvider]->determineDoubleReuseEncryptionMaterials() General Exception: " + e);

            throw new RuntimeException(e);
        }
    }

    private EncryptionMaterials determineDoubleEncryptionMaterialsForEncrypt() {
        logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleEncryptionMaterialsForEncrypt()");

        try {

            // if there is no current subsidiary encryption keypair, or it has expired then generate a new one
            if (this.strKpCurrentSubsidiaryFilename == null || this.strKpCurrentSubsidiaryFilename.isEmpty() || LocalDateTime.now().isAfter(this.datetimeKpCurrentSubsidiaryExpiryTime)) {
                generateSubsidiaryKP();
            }

            KeyPair skKP = new KeyPair(this.kpCurrentSubsidiary.getPublic(), null);

            EncryptionMaterials localEncryptionMaterials = new EncryptionMaterials(skKP);
            logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleEncryptionMaterialsForEncrypt() localEncryptionMaterials: " + localEncryptionMaterials.toString());

            localEncryptionMaterials.addDescription("mode", "doubleReuse");
            localEncryptionMaterials.addDescription("keyid", this.strKpCurrentSubsidiaryFilename);
            logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->determineDoubleEncryptionMaterialsForEncrypt() localEncryptionMaterials - adding description: mode=doubleReuse, keyid=" + strKpCurrentSubsidiaryFilename);

            return localEncryptionMaterials;

        } catch (Exception e) {
            logger.log(Level.SEVERE, "[DWEncryptionMaterialsProvider]->determineDoubleEncryptionMaterialsForEncrypt() General Exception: " + e);

            throw new RuntimeException(e);
        }
    }

    private void generateSubsidiaryKP() {
        logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->generateSubsidiaryKP()");

        try {

            // generate new subsidiary keypair
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);

            KeyPair kpSubsidiary = kpg.generateKeyPair();
            logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->generateSubsidiaryKP() kpSubsidiary: " + kpSubsidiary.toString());

            // encode private half (to DER format)
            byte[] bytesEnvKPPriv = kpSubsidiary.getPrivate().getEncoded();

            // generate a symmetric key to encrypt both halves of the subsidiary keypair
            // (required because the subsidiary keypair is too long to be encrypted with DKS, so DKS will encrypt the symmetric key instead)

            SecretKey skSymKey = KeyGenerator.getInstance("AES").generateKey();
            Cipher cipherSymKey = Cipher.getInstance("AES/GCM/NoPadding");
            cipherSymKey.init(Cipher.ENCRYPT_MODE, skSymKey);
            byte[] bytesCipherSymKeyIV = cipherSymKey.getIV();
            String b64SymKeyIV = new String(b64Encoder.encode(bytesCipherSymKeyIV));
            byte[] bytesSymKey = skSymKey.getEncoded();

            // encrypt the private half of the subsidiary keypair with the symmetric key and convert to base64
            byte[] bytesEncryptedKPSubsidiaryPriv = cipherSymKey.doFinal(bytesEnvKPPriv);
            String b64EncryptedKPSubsidiaryPriv = new String(b64Encoder.encode(bytesEncryptedKPSubsidiaryPriv));

            // encrypt the symmetric key with DataWorks' DKS
            String b64EncryptedSymKey = encryptWithDKS(bytesSymKey);

            String jsonSubsidiaryEncryptionMaterials = "{\"priv\":\"" + b64EncryptedKPSubsidiaryPriv + "\", \"symkeyiv\":\"" + b64SymKeyIV + "\", \"symkey\":\"" + b64EncryptedSymKey + "\"}";

            String strGUIDFilename = UUID.randomUUID().toString();

            // write keyfile to s3
            this.s3.putObject(this.strEncryptionKeypairsBucket, strGUIDFilename, jsonSubsidiaryEncryptionMaterials);

            // store locally as current KP and set expiry for max 24 hours
            this.strKpCurrentSubsidiaryFilename = strGUIDFilename;
            this.kpCurrentSubsidiary = kpSubsidiary;
            this.datetimeKpCurrentSubsidiaryExpiryTime = LocalDateTime.now().plusHours(24);

            logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->generateSubsidiaryKP() generated new subsidiary keypair, written to S3 with filename: " + strGUIDFilename);

        } catch (Exception e) {
            logger.log(Level.SEVERE, "[DWEncryptionMaterialsProvider]->generateSubsidiaryKP() General Exception: " + e);

            throw new RuntimeException(e);
        }
    }

    //* Note: TODO this function will need to be rewritten so that encryption is performed by the DKS
    private String encryptWithDKS(byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
        logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->encryptWithDKS()");

        // start of code to be replaced with call to DKS encryption method
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
        byte[] encryptedbytes = cipher.doFinal(data);
        // end of code to be replaced with call to DKS encryption method

        return new String(b64Encoder.encode(encryptedbytes));
    }

    //* Note: TODO this function will need to be rewritten so that decryption is performed by the DKS
    public byte[] decryptWithDKS(String msg)
            throws InvalidKeyException, UnsupportedEncodingException,
            IllegalBlockSizeException, BadPaddingException {
        logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->decryptWithDKS()");

        try {
            logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->decryptWithDKS() privateKey: " + this.privateKey.toString());
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

            cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
            byte[] bytesDecryptedString = cipher.doFinal(this.b64Decoder.decode(msg));
            logger.log(Level.INFO, "[DWEncryptionMaterialsProvider]->decryptWithDKS() strDecryptedString: " + new String(bytesDecryptedString));

            return bytesDecryptedString;

        } catch (Exception e) {
            logger.log(Level.SEVERE, "[DWEncryptionMaterialsProvider]->decryptWithDKS() General Exception: " + e);

            throw new RuntimeException(e);
        }
    }
}
