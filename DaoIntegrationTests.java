package tests;

import controller.EtudiantDAO;
import controller.NoteDAO;
import database.DatabaseConfig;
import model.Etudiant;
import model.Note;
import security.CryptoException;
import security.KeyManager;

import javax.crypto.SecretKey;

/**
 * Tests d'intégration pour les DAOs (nécessite PostgreSQL configuré)
 */
public class DaoIntegrationTests {

    public static void main(String[] args) {
        System.out.println("=== Tests d'intégration DAO ===\n");

        if (!DatabaseConfig.testConnection()) {
            System.out.println("Connexion à la base impossible: tests d'intégration ignorés.");
            return;
        }

        try {
            KeyManager.initialize();
            SecretKey key = KeyManager.getDefaultKey();

            EtudiantDAO etuDao = new EtudiantDAO(key);
            NoteDAO noteDao = new NoteDAO(key);

            etuDao.setEncryptionEnabled(true);
            noteDao.setEncryptionEnabled(true);

            String matricule = "TEST_MIG_" + System.currentTimeMillis();

            Etudiant etu = new Etudiant(matricule, "Test", "Integration", "Maths-Info", "INF", 1);

            System.out.println("Ajout de l'étudiant: " + matricule);
            boolean added = etuDao.ajouterEtudiant(etu);
            System.out.println("Ajout: " + added);
            assert added;

            Etudiant fetched = etuDao.rechercherParMatricule(matricule);
            System.out.println("Recherche: " + fetched);
            assert fetched != null;

            Note note = new Note(matricule, "TEST_UE101", 12.5);
            boolean noteAdded = noteDao.ajouterNote(note);
            System.out.println("Ajout note: " + noteAdded);
            assert noteAdded;

            Note fetchedNote = noteDao.rechercherNote(matricule, "TEST_UE101");
            System.out.println("Recherche note: " + fetchedNote);
            assert fetchedNote != null;

            // Cleanup
            boolean deletedNote = noteDao.supprimerNote(fetchedNote.getId());
            boolean deletedEtu = etuDao.supprimerEtudiant(matricule);
            System.out.println("Cleanup: note=" + deletedNote + ", etudiant=" + deletedEtu);

            System.out.println("\n✓ Tests d'intégration DAO réussis");

        } catch (CryptoException e) {
            System.err.println("Erreur crypto durant les tests d'intégration: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Erreur lors des tests d'intégration: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
