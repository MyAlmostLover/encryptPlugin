/*
 * MessageMail.java
 *
 * Created on 2018-08-10, 16:07
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

import com.sun.mail.imap.IMAPMessage;

import javax.mail.*;
import javax.mail.Message.RecipientType;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import java.io.Serializable;
//import java.time.ZoneId;
//import java.time.ZonedDateTime;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Created by Marc Nuri <marc@marcnuri.com> on 2018-08-10.
 */
@SuppressWarnings({"WeakerAccess", "unused"})
public class MessageMail implements Serializable {

    private static final long serialVersionUID = -1068972394742882009L;

    private static final String CET_ZONE_ID = "CET";
    public static final String HEADER_IN_REPLY_TO = "In-Reply-To";
    public static final String HEADER_REFERENCES = "References";

    private Long uid;
    private String messageId;
    private Long modseq;
    private List<String> from;
    private List<String>  replyTo;
    private List<Recipient> recipients;
    private Boolean encryptsm;
    private String subject;
    private Date receivedDate;
    private Long size;
    private Boolean flagged;
    private Boolean seen;
    private Boolean recent;
    private Boolean deleted;
    private String content;
    private List<Attachment> attachments;
    private List<String> references;
    private List<String> inReplyTo;
    private String encryptstatus;

    public String getEncryptstatus() {
        return encryptstatus;
    }

    public void setEncryptstatus(String encryptstatus) {
        this.encryptstatus = encryptstatus;
    }

    public Long getUid() {
        return uid;
    }

    public void setUid(Long uid) {
        this.uid = uid;
    }

    public String getMessageId() {
        return messageId;
    }

    public void setMessageId(String messageId) {
        this.messageId = messageId;
    }

    public Long getModseq() {
        return modseq;
    }

    public void setModseq(Long modseq) {
        this.modseq = modseq;
    }

    public List<String> getFrom() {
        return from;
    }

    public void setFrom(List<String> from) {
        this.from = from;
    }

    public List<String> getReplyTo() {
        return replyTo;
    }

    public void setReplyTo(List<String> replyTo) {
        this.replyTo = replyTo;
    }

    public List<Recipient> getRecipients() {
        return recipients;
    }

    public void setRecipients(List<Recipient> recipients) {
        this.recipients = recipients;
    }

    public Boolean isEncryptsm() {
        return encryptsm;
    }

    public void setEncryptsm(Boolean encryptsm) {
        this.encryptsm = encryptsm;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public Date getReceivedDate() {
        return receivedDate;
    }

    public void setReceivedDate(Date receivedDate) {
        this.receivedDate = receivedDate;
    }

    public Long getSize() {
        return size;
    }

    public void setSize(Long size) {
        this.size = size;
    }

    public Boolean getFlagged() {
        return flagged;
    }

    public void setFlagged(Boolean flagged) {
        this.flagged = flagged;
    }

    public Boolean getSeen() {
        return seen;
    }

    public void setSeen(Boolean seen) {
        this.seen = seen;
    }

    public Boolean getRecent() {
        return recent;
    }

    public void setRecent(Boolean recent) {
        this.recent = recent;
    }

    public Boolean getDeleted() {
        return deleted;
    }

    public void setDeleted(Boolean deleted) {
        this.deleted = deleted;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public List<Attachment> getAttachments() {
        return attachments;
    }

    public void setAttachments(List<Attachment> attachments) {
        this.attachments = attachments;
    }

    public List<String> getReferences() {
        return references;
    }

    public void setReferences(List<String> references) {
        this.references = references;
    }

    public List<String> getInReplyTo() {
        return inReplyTo;
    }

    public void setInReplyTo(List<String> inReplyTo) {
        this.inReplyTo = inReplyTo;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        MessageMail message = (MessageMail) o;
        return Objects.equals(uid, message.uid) &&
                Objects.equals(messageId, message.messageId) &&
                Objects.equals(modseq, message.modseq) &&
                Objects.equals(from, message.from) &&
                Objects.equals(replyTo, message.replyTo) &&
                Objects.equals(recipients, message.recipients) &&
                Objects.equals(subject, message.subject) &&
                Objects.equals(encryptsm, message.encryptsm) &&
                Objects.equals(receivedDate, message.receivedDate) &&
                Objects.equals(size, message.size) &&
                Objects.equals(flagged, message.flagged) &&
                Objects.equals(seen, message.seen) &&
                Objects.equals(recent, message.recent) &&
                Objects.equals(deleted, message.deleted) &&
                Objects.equals(content, message.content) &&
                Objects.equals(attachments, message.attachments) &&
                Objects.equals(references, message.references) &&
                Objects.equals(inReplyTo, message.inReplyTo);
    }

    @Override
    public int hashCode() {

        return Objects.hash(super.hashCode(), uid, messageId, modseq, from, replyTo, recipients, receivedDate, encryptsm, subject, size, flagged, seen, recent, deleted, content, attachments, references, inReplyTo);
    }

    /**
     * Maps an {@link com.sun.mail.imap.IMAPStore} to a {@link Message}.
     *
     * This method should only map those fields that are retrieved performed an IMAP fetch command (ENVELOPE,
     * UID, FLAGS...)
     *
     * To map other fields use a separate method.
     *
     * @param clazz Class of the new Message instance
//     * @param folder where the message is located
     * @param imapMessage original message to map
     * @return mapped Message with fulfilled envelope fields
     */
    public static <M extends MessageMail> M from(
            Class<M> clazz, MimeMessage imapMessage) {

        final M ret;
        if (imapMessage != null) {
            try {
                ret = clazz.newInstance();
//                ret.setUid(folder.getUID(imapMessage));
                ret.setMessageId(imapMessage.getMessageID());
                ret.setFrom(processAddress(imapMessage.getFrom()));
                ret.setReplyTo(processAddress(imapMessage.getReplyTo()));
                // Process only recipients received in ENVELOPE (don't use getAllRecipients)
                ret.setRecipients(Stream.of(
                        processAddress(RecipientType.TO, imapMessage.getRecipients(RecipientType.TO)),
                        processAddress(RecipientType.CC, imapMessage.getRecipients(RecipientType.CC)),
                        processAddress(RecipientType.BCC, imapMessage.getRecipients(RecipientType.BCC))
                ).flatMap(Collection::stream).collect(Collectors.toList()));
                ret.setSubject(imapMessage.getSubject());
                ret.setReceivedDate(imapMessage.getReceivedDate());
                ret.setSize((long)imapMessage.getSize());
                ret.setInReplyTo(Arrays.asList(
                        Optional.ofNullable(imapMessage.getHeader(HEADER_IN_REPLY_TO)).orElse(new String[0])));
                ret.setReferences(Arrays.asList(
                        Optional.ofNullable(imapMessage.getHeader(HEADER_REFERENCES)).orElse(new String[0])));
                final Flags flags = imapMessage.getFlags();
                ret.setFlagged(flags.contains(Flags.Flag.FLAGGED));
                ret.setSeen(flags.contains(Flags.Flag.SEEN));
                ret.setRecent(flags.contains(Flags.Flag.RECENT));
                ret.setDeleted(flags.contains(Flags.Flag.DELETED));
                String[] enheader = imapMessage.getHeader("X-IBC-SecMail");
                if (enheader!=null && enheader.length > 0 &&  enheader[0].equals("encrypted"))
                {
                    ret.setEncryptstatus("encrypted");
                }
                else
                {
                    ret.setEncryptstatus("plain");
                }
            } catch (ReflectiveOperationException | MessagingException e) {
                return null;
            }
        } else {
            ret = null;
        }
        return ret;
    }

    public static <F extends Folder & UIDFolder> MessageMail from(MimeMessage imapMessage) {
        return from(MessageMail.class, imapMessage);
    }

    private static List<Recipient> processAddress(RecipientType recipient, Address... addresses) {
        return processAddress(addresses).stream()
                .map(a -> new Recipient(recipient.toString(), a))
                .collect(Collectors.toList());
    }

    private static List<String> processAddress(Address... addresses) {
        return Stream.of(Optional.ofNullable(addresses).orElse(new Address[0]))
                .map(address -> {
                    if (address instanceof InternetAddress) {
                        final InternetAddress internetAddress = (InternetAddress) address;
                        return internetAddress.getPersonal() == null ? internetAddress.getAddress() :
                                String.format("\"%s\" <%s>", internetAddress.getPersonal(), internetAddress.getAddress());
                    } else {
                        return address.toString();
                    }
                })
                .collect(Collectors.toList());
    }

    /**
     * Validation Group interface for SMTP send operations
     */
    public interface SmtpSend {}

}
