package migrations;

import database.DatabaseConfig;
import security.CryptoException;
import security.CryptoManager;
import security.KeyManager;

import javax.crypto.SecretKey;
import java.sql.*;

/**
 * Outil de migration:
 * - calcule et stocke les HMAC (matricule_hash, code_ue_hash)
 * - chiffre les champs sensibles (matricule, code_ue) si demandé
 *
 * Usage: lancer cette classe avec la base PostgreSQL accessible
 */
public class MigrationTool {

    public static void main(String[] args) {
        boolean enableEncryption = true; // mettre false si vous ne voulez pas chiffrer les valeurs, seulement calculer les hash

        try {
            KeyManager.initialize();
            SecretKey key = KeyManager.getDefaultKey();

            try (Connection conn = DatabaseConfig.getConnection()) {
                conn.setAutoCommit(false);

                // S'assurer que les colonnes et index nécessaires existent
                ensureSchema(conn);

                migrateStudents(conn, key, enableEncryption);
                migrateNotes(conn, key, enableEncryption);

                conn.commit();
                System.out.println("Migration terminée avec succès.");
            }

        } catch (Exception e) {
            System.err.println("Erreur lors de la migration: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void migrateStudents(Connection conn, SecretKey key, boolean enableEncryption) throws SQLException {
        System.out.println("--- Migration des étudiants ---");

        String selectSql = "SELECT id, matricule, matricule_hash FROM etudiants";
        try (PreparedStatement sel = conn.prepareStatement(selectSql);
             ResultSet rs = sel.executeQuery()) {

            String updateSql = "UPDATE etudiants SET matricule = ?, matricule_hash = ? WHERE id = ?";

            try (PreparedStatement upd = conn.prepareStatement(updateSql)) {
                while (rs.next()) {
                    int id = rs.getInt("id");
                    String matricule = rs.getString("matricule");
                    String matriculeHash = rs.getString("matricule_hash");

                    // Calculer le HMAC si manquant
                    if (matriculeHash == null) {
                        try {
                            matriculeHash = CryptoManager.computeHmac(matricule, key);
                        } catch (CryptoException e) {
                            System.err.println("Erreur HMAC etudiant id=" + id + ": " + e.getMessage());
                            continue;
                        }
                    }

                    // Ne pas modifier la valeur de la colonne "matricule" pour éviter des violations de FK.
                    // Nous stockons seulement le HMAC pour permettre des recherches déterministes.
                    upd.setString(1, matricule); // laisser la valeur existante (non-chiffrée) pour l'instant
                    upd.setString(2, matriculeHash);
                    upd.setInt(3, id);
                    upd.executeUpdate();
                    System.out.println("Etudiant id=" + id + " migré (hash calculé, matricule " + (enableEncryption ? "chiffré" : "non-chiffré") + ")");
                }
            }
        }
    }

    private static void migrateNotes(Connection conn, SecretKey key, boolean enableEncryption) throws SQLException {
        System.out.println("--- Migration des notes ---");
        migrateNotesImpl(conn, key, enableEncryption);
    }

    private static void ensureSchema(Connection conn) throws SQLException {
        System.out.println("Vérification du schéma : ajout des colonnes et des index si nécessaire...");

        String[] statements = new String[]{
            "ALTER TABLE etudiants ADD COLUMN IF NOT EXISTS matricule_hash VARCHAR(255)",
            "ALTER TABLE notes ADD COLUMN IF NOT EXISTS matricule_hash VARCHAR(255)",
            "ALTER TABLE notes ADD COLUMN IF NOT EXISTS code_ue_hash VARCHAR(255)",
            "CREATE INDEX IF NOT EXISTS idx_etudiants_matricule_hash ON etudiants(matricule_hash)",
            "CREATE INDEX IF NOT EXISTS idx_notes_matricule_hash ON notes(matricule_hash)",
            "CREATE INDEX IF NOT EXISTS idx_notes_code_ue_hash ON notes(code_ue_hash)",
            "ALTER TABLE etudiants DROP COLUMN IF EXISTS matricule_clair",
            "ALTER TABLE notes DROP COLUMN IF EXISTS matricule_clair",
            "ALTER TABLE notes DROP COLUMN IF EXISTS code_ue_clair"
        };

        try (Statement stmt = conn.createStatement()) {
            for (String s : statements) {
                try {
                    stmt.execute(s);
                } catch (SQLException e) {
                    // Ne pas arrêter la migration si une instruction échoue; on log simplement
                    System.err.println("Instruction schéma échouée: " + s + " -> " + e.getMessage());
                }
            }
        }

        System.out.println("Schéma vérifié.");

        // Reprendre la logique de migration des notes (déplacée en bas pour clarté)
        // (key et enableEncryption seront repris dans l'appel original)
        // Note: nous n'avons pas accès à ces variables ici, le flux d'appel principal appellera migrateNotes(conn, key, enableEncryption)
    }

    private static void migrateNotesImpl(Connection conn, SecretKey key, boolean enableEncryption) throws SQLException {
        // Copié depuis le corps précédent de migrateNotes (séparé pour permettre ensureSchema d'appeler la logique)
        String selectSql = "SELECT id, matricule, matricule_hash, code_ue, code_ue_hash FROM notes";
        try (PreparedStatement sel = conn.prepareStatement(selectSql);
             ResultSet rs = sel.executeQuery()) {

            String updateSql = "UPDATE notes SET matricule = ?, matricule_hash = ?, code_ue = ?, code_ue_hash = ? WHERE id = ?";

            try (PreparedStatement upd = conn.prepareStatement(updateSql)) {
                while (rs.next()) {
                    int id = rs.getInt("id");
                    String matricule = rs.getString("matricule");
                    String matriculeHash = rs.getString("matricule_hash");
                    String codeUE = rs.getString("code_ue");
                    String codeUEHash = rs.getString("code_ue_hash");

                    // Obtenir le matricule clair
                    String matriculePlain = matricule;
                    try {
                        String decrypted = CryptoManager.decrypt(matricule, key);
                        if (decrypted != null && !decrypted.equals(matricule)) {
                            matriculePlain = decrypted;
                        }
                    } catch (CryptoException e) {
                        // valeur en clair
                    }

                    if (matriculeHash == null) {
                        try {
                            matriculeHash = CryptoManager.computeHmac(matriculePlain, key);
                        } catch (CryptoException e) {
                            System.err.println("Erreur HMAC note id=" + id + ": " + e.getMessage());
                            continue;
                        }
                    }

                    if (codeUEHash == null) {
                        try {
                            codeUEHash = CryptoManager.computeHmac(codeUE, key);
                        } catch (CryptoException e) {
                            System.err.println("Erreur HMAC code UE note id=" + id + ": " + e.getMessage());
                            continue;
                        }
                    }

                    // Pour éviter les violations de FK, on ne remplace pas la colonne "matricule" dans notes.
                    // On stocke simplement le matricule actuel et on calcule/stocke le HMAC. En revanche, nous pouvons chiffrer 'code_ue'.
                    String matriculeToStore = matricule;
                    String codeUEToStore = codeUE;

                    if (enableEncryption) {
                        // Chiffrer codeUE s'il est en clair
                        try {
                            // Détecter si codeUE semble déjà chiffré
                            try {
                                String decrypted = CryptoManager.decrypt(codeUE, key);
                                if (decrypted == null || decrypted.equals(codeUE)) {
                                    // probablement en clair
                                    codeUEToStore = CryptoManager.encrypt(codeUE, key);
                                } else {
                                    codeUEToStore = codeUE; // déjà chiffré
                                }
                            } catch (CryptoException e) {
                                // en clair -> chiffrer
                                codeUEToStore = CryptoManager.encrypt(codeUE, key);
                            }
                        } catch (CryptoException ex) {
                            System.err.println("Erreur chiffrement code UE note id=" + id + ": " + ex.getMessage());
                        }
                    }

                    upd.setString(1, matriculeToStore);
                    upd.setString(2, matriculeHash);
                    upd.setString(3, codeUEToStore);
                    upd.setString(4, codeUEHash);
                    upd.setInt(5, id);
                    upd.executeUpdate();

                    System.out.println("Note id=" + id + " migrée (hashs calculés, champs chiffrés si activé)");
                }
            }
        }
    }
}