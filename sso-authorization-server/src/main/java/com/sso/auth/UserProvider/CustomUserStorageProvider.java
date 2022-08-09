package com.sso.auth.UserProvider;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CustomUserStorageProvider implements UserStorageProvider,
        UserLookupProvider,
        CredentialInputValidator,
        UserQueryProvider {



    public  List<CustomUser> getListUser(RealmModel realm) {
        List<CustomUser> listUser = new ArrayList<CustomUser>();
        List<String> roles = new ArrayList<>();
        roles.add("user");
        roles.add("admin");
//        CustomUser newUser = new CustomUser(ksession, realm, model,"admin", "123","fad","dasda",new Date(),roles);
//        newUser.grantRole(KeycloakModelUtils.getRoleFromString(realm, "admin"));
        listUser.add(new CustomUser(ksession, realm, model,"admin", "123","fad","dasda",new Date(),roles));
        listUser.add(new CustomUser(ksession, realm, model,"user1", "fdsf","fad","dasda",new Date(),roles));
        listUser.add(new CustomUser(ksession, realm, model,"user2", "gf","fad","dasda",new Date(),roles));
        listUser.add(new CustomUser(ksession, realm, model,"user3", "ga","fad","dasda",new Date(),roles));
        return listUser;
    }

    private static final Logger log = LoggerFactory.getLogger(CustomUserStorageProvider.class);
    private KeycloakSession ksession;
    private ComponentModel model;

    public CustomUserStorageProvider(KeycloakSession ksession, ComponentModel model) {
        this.ksession = ksession;
        this.model = model;
    }

    @Override
    public void close() {
        log.info("[I30] close()");
    }

    @Override
    public UserModel getUserById(String id, RealmModel realm) {
        log.info("[I35] getUserById({})",id);
        StorageId sid = new StorageId(id);
        return getUserByUsername(sid.getExternalId(),realm);
    }

    @Override
    public UserModel getUserByUsername(String username, RealmModel realm) {
        log.info("[I41] getUserByUsername({})",username);
//        try ( Connection c = DbUtil.getConnection(this.model)) {
//            PreparedStatement st = c.prepareStatement("select username, firstName,lastName, email, birthDate from users where username = ?");
//            st.setString(1, username);
//            st.execute();
//            ResultSet rs = st.getResultSet();
//            if ( rs.next()) {
//                return mapUser(realm,rs);
//            }
//            else {
//                return null;
//            }
//        }
//        catch(SQLException ex) {
//            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
//        }
        AtomicReference<CustomUser> result = new AtomicReference<>();
        getListUser(realm).forEach((user) -> {
            if (user.getUsername().equals(username)) {
                result.set(user);
            }
        });

        CustomUser resultUser= result.get();
        for (String role: resultUser.getRoles()) {
        if (!resultUser.hasRole(KeycloakModelUtils.getRoleFromString(realm, role)))
            resultUser.grantRole(KeycloakModelUtils.getRoleFromString(realm, role));
        }
        return resultUser;
    }

    @Override
    public UserModel getUserByEmail(String email, RealmModel realm) {
        log.info("[I48] getUserByEmail({})",email);
        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement("select username, firstName,lastName, email, birthDate from users where email = ?");
            st.setString(1, email);
            st.execute();
            ResultSet rs = st.getResultSet();
            if ( rs.next()) {
                return mapUser(realm,rs);
            }
            else {
                return null;
            }
        }
        catch(SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
        }
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        log.info("[I57] supportsCredentialType({})",credentialType);
        return PasswordCredentialModel.TYPE.endsWith(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        log.info("[I57] isConfiguredFor(realm={},user={},credentialType={})",realm.getName(), user.getUsername(), credentialType);
        // In our case, password is the only type of credential, so we allways return 'true' if
        // this is the credentialType
        return supportsCredentialType(credentialType);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
        log.info("[I57] isValid(realm={},user={},credentialInput.type={})",realm.getName(), user.getUsername(), credentialInput.getType());
        if( !this.supportsCredentialType(credentialInput.getType())) {
            return false;
        }
        StorageId sid = new StorageId(user.getId());
        String username = sid.getExternalId();

//        try ( Connection c = DbUtil.getConnection(this.model)) {
//            PreparedStatement st = c.prepareStatement("select password from users where username = ?");
//            st.setString(1, username);
//            st.execute();
//            ResultSet rs = st.getResultSet();
//            if ( rs.next()) {
//                String pwd = rs.getString(1);
//                return pwd.equals(credentialInput.getChallengeResponse());
//            }
//            else {
//                return false;
//            }
//        }
//        catch(SQLException ex) {
//            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
//        }
        return true;
    }

    // UserQueryProvider implementation

    @Override
    public int getUsersCount(RealmModel realm) {
        log.info("[I93] getUsersCount: realm={}", realm.getName() );
//        try ( Connection c = DbUtil.getConnection(this.model)) {
//            Statement st = c.createStatement();
//            st.execute("select count(*) from users");
//            ResultSet rs = st.getResultSet();
//            rs.next();
//            return rs.getInt(1);
//        }
//        catch(SQLException ex) {
//            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
//        }
        return 4;
    }

    @Override
    public List<UserModel> getUsers(RealmModel realm) {
        return getUsers(realm,0, 5000); // Keep a reasonable maxResults
    }

    @Override
    public List<UserModel> getUsers(RealmModel realm, int firstResult, int maxResults) {
        log.info("[I113] getUsers: realm={}", realm.getName());

//        try ( Connection c = DbUtil.getConnection(this.model)) {
//            PreparedStatement st = c.prepareStatement("select username, firstName,lastName, email, birthDate from users order by username limit ? offset ?");
//            st.setInt(1, maxResults);
//            st.setInt(2, firstResult);
//            st.execute();
//            ResultSet rs = st.getResultSet();
//            List<UserModel> users = new ArrayList<>();
//            while(rs.next()) {
//                users.add(mapUser(realm,rs));
//            }
//            return users;
//        }
//        catch(SQLException ex) {
//            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
//        }
        List<UserModel> result = new ArrayList<>();
        getListUser(realm).forEach((user)->result.add(user));
        return result;
    }

    @Override
    public List<UserModel> searchForUser(String search, RealmModel realm) {
        return searchForUser(search,realm,0,5000);
    }

    @Override
    public List<UserModel> searchForUser(String search, RealmModel realm, int firstResult, int maxResults) {
        log.info("[I139] searchForUser: realm={}", realm.getName());

        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement("select username, firstName,lastName, email, birthDate from users where username like ? order by username limit ? offset ?");
            st.setString(1, search);
            st.setInt(2, maxResults);
            st.setInt(3, firstResult);
            st.execute();
            ResultSet rs = st.getResultSet();
            List<UserModel> users = new ArrayList<>();
            while(rs.next()) {
                users.add(mapUser(realm,rs));
            }
            return users;
        }
        catch(SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
        }
    }

    @Override
    public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm) {
        return searchForUser(params,realm,0,5000);
    }

    @Override
    public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm, int firstResult, int maxResults) {
        return getUsers(realm, firstResult, maxResults);
    }

    @Override
    public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group, int firstResult, int maxResults) {
        return Collections.emptyList();
    }

    @Override
    public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group) {
        return Collections.emptyList();
    }

    @Override
    public List<UserModel> searchForUserByUserAttribute(String attrName, String attrValue, RealmModel realm) {
        return Collections.emptyList();
    }


    //------------------- Implementation
    private UserModel mapUser(RealmModel realm, ResultSet rs) throws SQLException {

        DateFormat fmt = new SimpleDateFormat("yyyy-MM-dd");
        CustomUser user = new CustomUser.Builder(ksession, realm, model, rs.getString("username"))
                .email(rs.getString("email"))
                .firstName(rs.getString("firstName"))
                .lastName(rs.getString("lastName"))
                .birthDate(rs.getDate("birthDate"))
                .build();

        return user;
    }
}