
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdifReader;

import java.io.*;


/**
 * Created by SLazarev on 24.10.2017.
 */
public class AppStart {
    public static void main(String[] args) throws Exception {
        File folder = new File("files/");
        File[] listOfFiles = folder.listFiles();
        if (listOfFiles == null) {
            System.out.println("Не найдены документы подходящего формата!");
            return;
        }
        File errUsersCertList = new File("errorCertificateUsers.txt");
        File errUsersMailList = new File("errorMailUsers.txt");
        FileWriter writerForErrUsersCert = new FileWriter(errUsersCertList);
        FileWriter writerForErrUsersMail = new FileWriter(errUsersMailList);
        for (File file : listOfFiles) {
            if (file.getName().endsWith(".ldif")) {
                File newFile = new File("newFiles/" + file.getName());
                FileWriter writerForNewLdifEntry = new FileWriter(newFile);
                LdifReader ldifReader;
                ldifReader = new LdifReader(file);
                while (ldifReader.hasNext()) {
                    LdifEntry ldifEntry = ldifReader.next();
                    Utils.dnAttributeHandler(ldifEntry);
                    Utils.objectClassAttributeHandler(ldifEntry);
                    Utils.certificateIssuerDN_Handler(ldifEntry, "rugov-certificateissuerdn");
                    Utils.certificateIssuerDN_Handler(ldifEntry, "rugov-CertificateIssuerDN-normalized");
                    Utils.userCertificateHandler(ldifEntry, writerForErrUsersCert);
                    Utils.memberAttributeHandler(ldifEntry);
                    Utils.mailAttributeHandler(ldifEntry, writerForErrUsersMail);

                    writerForNewLdifEntry.write(ldifEntry.toString());
                }
                writerForNewLdifEntry.close();
            }
        }
        writerForErrUsersMail.close();
        writerForErrUsersCert.close();
    }
}
