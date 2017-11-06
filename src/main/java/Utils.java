import org.apache.directory.api.ldap.model.entry.BinaryValue;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.name.Dn;
import sun.security.x509.X509CertImpl;

import javax.xml.bind.DatatypeConverter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Base64;

/**
 * Created by SLazarev on 25.10.2017.
 */

public class Utils {
    static void certificateIssuerDN_Handler(LdifEntry ldifEntry, String attributeName) {
        if (ldifEntry.get(attributeName) == null) {
            return;
        }
        byte[] attributeByteArray = ldifEntry.get(attributeName).get().getBytes();
        String withReplaceOid = new String(DatatypeConverter.parseBase64Binary(Base64.getEncoder().encodeToString(attributeByteArray))).replace("OID.", "");
        BinaryValue binaryValue = new BinaryValue(withReplaceOid.getBytes());
        ldifEntry.getEntry().get(attributeName).clear();
        try {
            ldifEntry.get(attributeName).add(binaryValue);
        } catch (LdapInvalidAttributeValueException e) {
            System.out.println("Не удалось изменить следующий аттрибут: " + attributeName);
            e.printStackTrace();
        }
    }

    static void userCertificateHandler(LdifEntry ldifEntry, FileWriter writer) throws LdapException, IOException {
        if (ldifEntry.get("userCertificate") == null) {
            return;
        }
        try {
            new X509CertImpl(ldifEntry.getEntry().get("userCertificate").get().getBytes());
            ldifEntry.getEntry().add("userCertificate;binary", ldifEntry.getEntry().get("userCertificate").get());
            ldifEntry.get("userCertificate").clear();
        } catch (CertificateException e) {
            writer.write(ldifEntry.getDn().toString() + "\n");
            ldifEntry.getEntry().remove(ldifEntry.getEntry().get("userCertificate"));
        }
    }

    static void memberAttributeHandler(LdifEntry ldifEntry) throws LdapException {
        if (ldifEntry.get("member") == null) {
            return;
        }
        String[] attributeValues = ldifEntry.get("member").toString().replace("member: ", "").split("\n");
        String[] newAttributeValues = new String[attributeValues.length];
        for (int i = 0; i < attributeValues.length; i++) {
            newAttributeValues[i] = attributeValues[i].replace("cn=pgz,o=pgz", "ou=pgz,dc=zakupki,dc=gov,dc=ru");
        }
        ldifEntry.getEntry().remove(ldifEntry.getEntry().get("member"));
        ldifEntry.getEntry().add("member", newAttributeValues);
    }

    static void dnAttributeHandler(LdifEntry ldifEntry) throws LdapInvalidDnException {
        if (ldifEntry.getDn().getName() == null) {
            return;
        }
        if (ldifEntry.getDn().getName().contains("cn=pgz,o=pgz")) {
            ldifEntry.setDn(new Dn(ldifEntry.getDn().getRdns().get(0).getName(), "ou=pgz", "dc=zakupki", "dc=gov", "dc=ru"));
        }
    }

    static void objectClassAttributeHandler(LdifEntry ldifEntry) throws LdapInvalidAttributeValueException {
        if (ldifEntry.get("objectClass") == null) {
            return;
        }
        if (ldifEntry.get("objectClass").contains("inetorgperson") &&
                !ldifEntry.get("objectClass").contains("EISPerson")) {
            ldifEntry.get("objectClass").add("EISPerson");
        }
    }

    static void mailAttributeHandler(LdifEntry ldifEntry, FileWriter writer) throws LdapException, IOException {
        if (ldifEntry.get("mail") == null) {
            return;
        }
        if (!ldifEntry.get("mail").isHumanReadable()) {
            ldifEntry.getEntry().remove(ldifEntry.getEntry().get("mail"));
            writer.write(ldifEntry.getDn().toString() + "\n");
        }
    }
}
