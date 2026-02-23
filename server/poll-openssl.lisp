(in-package #:http2/openssl)

(defsection @SSL (:title "SSL handling")
  "Wrapper library over openssl functions.

@OPENSSL-ENDPOINT wraps the SSL parameter used in openssl functions.

@OPENSSL-CONTEXT wraps the CTX parameter used in openssl functions"
  (bio-should-retry function)
  (@openssl-endpoint section)
  (@openssl-context section)
  (@ssl-ops section)
  (@ssl-errors section))

(defsection @SSL-errors (:title "Signalled errors")
  "Error conditions from openssl api calls are represented by appropriate error
conditions. They are descended from the COMMUNICATION-ERROR.

See manual page for SSL_get_error for the overview."
  (handle-ssl-errors function)
  (communication-error condition)
  (simple-communication-error condition)
  (ssl-blocked condition)
  (ssl-wants-read condition)
  (ssl-wants-write condition)
  (peer-sent-close-notify condition)
  (ssl-error-condition condition)
  (ssl-syscall-error condition)
  (other-ssl-error condition))

(define-condition ssl-error-condition (communication-error)
  ((codes :accessor get-codes :initarg :codes))
  (:report (lambda (condition out)
             (format out "Peer sent an alert: ~{~a~%~}"
                     (mapcar (lambda (code)
                               (foreign-string-to-lisp (err-reason-error-string code)))
                             (get-codes condition)))))
  (:documentation "An error condition on SSL side that is not handled separately.

The list of error codes is in openssl/sslerr.h.

A non-recoverable, fatal error in the SSL library occurred, usually a protocol
 error.  The OpenSSL error queue contains more information on the error. If this
 error occurs then no further I/O operations should be performed on the
 connection and SSL_shutdown() must not be called."))

(defmethod print-object ((object ssl-error-condition) stream)
  (if *print-escape*
      (print-unreadable-object (object stream :type t :identity nil)
        (dolist (code (get-codes object))
          (format stream "~x: ~a" code
                  (foreign-string-to-lisp (err-reason-error-string code))))
        (format stream " on ~a" (get-medium object)))
      (call-next-method)))

(defun get-ssl-errors ()
  "Get SSL error and either close connection immediately (for some known and
expected errors) or let user handle it."
  (loop for err = (err-get-error)
        until (zerop err)
        collect err))

(define-condition ssl-syscall-error (ssl-error-condition http2/tcpip:syscall-error)
  ()
  (:documentation "Some non-recoverable, fatal I/O error occurred. The OpenSSL error
 queue may contain more information on the error. For socket I/O on Unix
 systems, consult errno for details. If this error occurs then no further I/O
 operations should be performed on the connection and SSL_shutdown() must not be
 called.

 This value can also be returned for other errors, check the error queue for
 details."))

(define-condition simple-communication-error (simple-condition communication-error)
  ())

(define-condition peer-sent-alert (communication-error)
  ()
  (:documentation  "The TLS/SSL peer has closed the connection for writing by sending the
close_notify alert.  No more data can be read.  This does not necessarily
indicate that the underlying transport has been closed."))

(define-condition peer-sent-close-notify (peer-sent-alert)
  ()
  (:documentation  "The TLS/SSL peer has closed the connection for writing by sending the
close_notify alert.  No more data can be read.  This does not necessarily
indicate that the underlying transport has been closed.")
  ;; To test: run a curl request
  (:report "Peer closed TLS connection."))

(define-condition ssl-blocked (communication-error)
  ()
  (:documentation "The operation did not complete and can be retried later."))

(define-condition ssl-wants-read (ssl-blocked)
  ()
  (:documentation
   "The last operation was a read operation from a nonblocking BIO. Not enough data
was available at this time to complete the operation.  If at a later time the
underlying BIO has data available for reading the same function can be called
again.")
  (:report "Not enough data for SSL read. Waiting for more data normally fixes this"))

(define-condition ssl-wants-write (ssl-blocked)
  ()
  (:documentation  ""))

(define-condition retry-flag-not-set (communication-error)
  ()
  (:documentation "Openss "))

(define-condition unexpected-eof (communication-error)
  ()
  (:documentation
   "On an unexpected EOF, versions before OpenSSL 3.0 returned SSL_ERROR_SYSCALL,
nothing was added to the error stack, and errno was 0."))

(define-condition other-ssl-error (communication-error)
  ((code :accessor get-code :initarg :code))
  (:documentation "ssl-get-error return code that we do not handle (yet)"))

(defun handle-ssl-errors* (client ret)
  "Raise appropriate error after a failed openssl call.

Raises one of SIMPLE-COMMUNICATION-ERROR, SSL-WANTS-WRITE, SSL-WANTS-READ,
PEER-SENT-CLOSE-NOTIFY, SSL-ERROR-CONDITION, SSL-SYSCALL-ERROR, or
OTHER-SSL-ERROR.

If ret>0 (no fail), returns nil."
  ;; after SSL_connect(), SSL_accept(),SSL_do_handshake(), SSL_read_ex(),
  ;; SSL_read(), SSL_peek_ex(),SSL_peek(), SSL_shutdown(), SSL_write_ex() or
  ;; SSL_write()

  (let* ((ssl (tls-endpoint-core-ssl client))
         (wbio (tls-endpoint-core-rbio client))
         (err-code (ssl-get-error ssl ret)))
    (cond
      ;; after ssl read
      ((= err-code ssl-error-want-write)
       (when (zerop (bio-test-flags wbio bio-flags-should-retry))
         (error 'simple-communication-error :format-control "Retry flag should be set."
                                            :medium client))
       (error 'ssl-wants-write :medium client))
      ((= err-code ssl-error-want-read)
       ;; This is relevant for accept call and handled in loop
       ;; may be needed for pull phase
       ;; is this needed?
       (when (zerop (bio-test-flags wbio bio-flags-should-retry))
         (error 'simple-communication-error :format-control "Retry flag should be set."
                                            :medium client))
       (error 'ssl-wants-read))
      ((= err-code ssl-error-none) nil) ; this should happen iff ret > 0
      ((= err-code ssl-error-zero-return) (error 'peer-sent-close-notify :medium client))
      ((= err-code ssl-error-ssl) (error 'ssl-error-condition :medium client :codes (get-ssl-errors)))
      ((= err-code ssl-error-syscall)
       (let ((errno (http2/tcpip:errno)))
         (if (zerop errno)
             (error 'unexpected-eof :medium client)
             (error 'ssl-syscall-error :codes (get-ssl-errors) :errno errno :medium client))))
      (t (error 'other-ssl-error :code err-code :medium client)))))

(defun handle-ssl-errors (client ret)
  "Check real error after a call to SSL_connect, SSL_accept,
SSL_do_handshake, SSL_read_ex, SSL_read, SSL_peek_ex, SSL_peek, SSL_shutdown,
SSL_write_ex or SSL_write.

If the operation was successfully completed, do nothing.

If it is a harmless one (want read or want write), try to process the data.

Raise error otherwise."
  (handler-case (handle-ssl-errors* client ret)
    (ssl-wants-read () (remove-state client 'neg-bio-needs-read))))


(defsection @ssl-ops ()
  "Use ENCRYPT-SOME* and SSL-READ"
  (encrypt-some* function)
  (read-encrypted-from-openssl* function)
  (write-octets-to-decrypt* function)
  (ssl-read function)
  (maybe-init-ssl function)
  (ssl-peek function))

(defun encrypt-some* (client vector from to)
  "Encrypt octets in VECTOR between FROM and TO. Return number of octets
processed, or raise appropriate error. You can read the encrypted octets later by READ-ENCRYPTED-FROM-OPENSSL*."
  (with-pointer-to-vector-data (buffer vector)
  (handler-case
      (let* ((ssl (tls-endpoint-core-ssl client))
             (res (ssl-write ssl (inc-pointer buffer from) (- to from))))
        (cond
          ((plusp res)
           (add-state client 'can-read-bio)
           res)
          ;; no-star handle-ssl-errors masks SSL-WANTS-READ
          (t (handle-ssl-errors* client res)
             0)))
    (ssl-blocked ()
      (remove-state client 'can-write-ssl)))))

(defun bio-should-retry (wbio)
  (bio-test-flags wbio bio-flags-should-retry))

(defun read-encrypted-from-openssl* (client vec size)
  (declare ((simple-array (unsigned-byte 8)) vec)
           (fixnum size))
  (with-pointer-to-vector-data (buffer vec)
    (let ((res (bio-read% (tls-endpoint-core-wbio client) buffer size)))
      (cond ((plusp res)
             (add-state client 'has-data-to-write)
             res)
            ((zerop (bio-should-retry (tls-endpoint-core-wbio client)))
             (error "Failed to read from bio, and cant retry"))
            (t
             (remove-state client 'can-read-bio)
             0)))))

(defun write-octets-to-decrypt* (client vector from to)
  "Send octets in VECTOR for decryption. Read result with SSL-READ later."
  (with-pointer-to-vector-data (buffer vector)
    (let ((written (bio-write (tls-endpoint-core-rbio client)
                              (inc-pointer buffer from)
                              (- to from))))
      (unless (plusp written) (error "Bio-write failed"))
      written)))

(defun maybe-init-ssl (client)
  "If SSL is not initialized yet, initialize it."
  (cond
    ((zerop (ssl-is-init-finished (tls-endpoint-core-ssl client)))
     (handle-ssl-errors client (ssl-accept (tls-endpoint-core-ssl client))))
    (t (remove-state client 'ssl-init-needed)
       (add-state client 'can-read-bio))))

;;;; Read SSL
(defun ssl-read (client vec size)
   "Move up to SIZE octets from the decrypted SSL ③ to the VEC.

Return 0 when no data are available. Possibly remove CAN-READ-SSL and/or
NEG-BIO-NEEDS-READ flags."
   (let ((res
          (with-pointer-to-vector-data (buffer vec)
            (ssl-read% (tls-endpoint-core-ssl client) buffer size))))
     (handle-ssl-errors client res)
     (unless (= res size) (remove-state client 'can-read-ssl))
     (max 0 res)))

(defun ssl-peek (client max-size)
   "Move up to SIZE octets from the decrypted SSL ③ to the VEC.

Return 0 when no data are available."
  (unless (null-pointer-p (tls-endpoint-core-ssl client))
    (let* ((vec (make-octet-buffer max-size))
           (res
             (with-pointer-to-vector-data (buffer vec)
               (http2/openssl::ssl-peek% (tls-endpoint-core-ssl client) buffer max-size))))
      (handle-ssl-errors client res)
      (values (subseq vec 0 (max 0 res)) res))))
