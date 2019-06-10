/*
 * Credentials.java
 *
 * Created on 2018-08-15, 18:10
 *
 * Copyright 2018 Marc Nuri
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package cordova.encryption;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.io.Serializable;
import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.Objects;

/**
 * Created by Marc Nuri <marc@marcnuri.com> on 2018-08-15.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true, value = {"authorities"})
public class Credentials implements Serializable {

    private static final long serialVersionUID = -3763522029969923952L;

    private String encrypted;
    private String salt;
    private String serverHost;
    private Integer serverPort = 993;
    private String user;
    private String password;
    private Boolean imapSsl = true;
    private String smtpHost;
    private Integer smtpPort = 587;
    private Boolean smtpSsl = false;
    private ZonedDateTime expiryDate;
    private String code;

    private String status;
    private String errorCode;
    private String message;
    private String unionId;

    private String domain="";

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getUnionId() {
        return unionId;
    }

    public void setUnionId(String unionId) {
        this.unionId = unionId;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getEncrypted() {
        return encrypted;
    }

    public void setEncrypted(String encrypted) {
        this.encrypted = encrypted;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public String getServerHost() {
        return serverHost;
    }

    public void setServerHost(String serverHost) {
        this.serverHost = serverHost;
    }

    public Integer getServerPort() {
        return serverPort;
    }

    public void setServerPort(Integer serverPort) {
        this.serverPort = serverPort;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Boolean getImapSsl() {
        return imapSsl;
    }

    public void setImapSsl(Boolean imapSsl) {
        this.imapSsl = imapSsl;
    }

    public String getSmtpHost() {
        return smtpHost;
    }

    public void setSmtpHost(String smtpHost) {
        this.smtpHost = smtpHost;
    }

    public Integer getSmtpPort() {
        return smtpPort;
    }

    public void setSmtpPort(Integer smtpPort) {
        this.smtpPort = smtpPort;
    }

    public Boolean getSmtpSsl() {
        return smtpSsl;
    }

    public void setSmtpSsl(Boolean smtpSsl) {
        this.smtpSsl = smtpSsl;
    }

    public ZonedDateTime getExpiryDate() {
        return expiryDate;
    }

    public void setExpiryDate(ZonedDateTime expiryDate) {
        this.expiryDate = expiryDate;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        Credentials that = (Credentials) o;
        return Objects.equals(encrypted, that.encrypted) &&
                Objects.equals(salt, that.salt) &&
                Objects.equals(serverHost, that.serverHost) &&
                Objects.equals(serverPort, that.serverPort) &&
                Objects.equals(user, that.user) &&
                Objects.equals(password, that.password) &&
                Objects.equals(imapSsl, that.imapSsl) &&
                Objects.equals(smtpHost, that.smtpHost) &&
                Objects.equals(smtpPort, that.smtpPort) &&
                Objects.equals(smtpSsl, that.smtpSsl) &&
                Objects.equals(expiryDate, that.expiryDate);
    }

    @Override
    public int hashCode() {

        return Objects.hash(super.hashCode(), encrypted, salt, serverHost, serverPort, user, password, imapSsl, smtpHost, smtpPort, smtpSsl, expiryDate);
    }

    /**
     * Validation Group interface for login
     */
    public interface Login {}

}
