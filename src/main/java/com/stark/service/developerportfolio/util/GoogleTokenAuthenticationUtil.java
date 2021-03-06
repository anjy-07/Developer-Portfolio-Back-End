package com.stark.service.developerportfolio.util;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.stark.service.developerportfolio.model.firestore.UserProfileData;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;

public class GoogleTokenAuthenticationUtil {
    private static final JacksonFactory jacksonFactory = new JacksonFactory();
    private static final HttpTransport httpTransport = new NetHttpTransport();
    private static final String CLIENT_ID = "865958668201-3upung40a7uuidhh47hp34v91rggsgl8.apps.googleusercontent.com";
    private static UserProfileData userProfileData;

    public static boolean authenticateGoogleOauthToken(String googleAuthTokenString) throws GeneralSecurityException, IOException {
        boolean emailVerified = false;

        if(userProfileData == null) {
            userProfileData = new UserProfileData();
        }
        GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(httpTransport, jacksonFactory)
                .setAudience(Collections.singletonList(CLIENT_ID))
                .build();

        GoogleIdToken idToken = verifier.verify(googleAuthTokenString);

        if (idToken != null) {
            GoogleIdToken.Payload payload = idToken.getPayload();

            userProfileData.setEmail(payload.getSubject());
            userProfileData.setEmail(payload.getEmail());
            userProfileData.setName((String) payload.get("name"));
            userProfileData.setPictureUrl((String) payload.get("picture"));
            userProfileData.setLocale((String) payload.get("locale"));
            emailVerified = Boolean.valueOf(payload.getEmailVerified());
            System.out.println(userProfileData.toString());
        }
        return emailVerified;
    }

    public static UserProfileData getUserProfileData() {
        return userProfileData;
    }

}
