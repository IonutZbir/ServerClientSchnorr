# TODO

- [] Modificare la fase di handshake: il client fa un richiesta di handshake, il server risponde poi con la lista dei gruppi crittografici. Il client verifica nella sua lista se i gruppi inviati dal server sono presenti e ne sceglie uno inviando poi al server il gruppo scelto. Nel caso in cui il client non abbia a disposizione nessun gruppo crittografico invia a server un messaggio NOK, chiudendo la connessione.
- [] Ciascun account deve essere identificato a lato serever dall'username inserito dall'utente (uno qualsiasi) più un uuid. Il client, al momento della registrazione deve inviare al server, username, pk, e l'hash della chiave pubblica. All'interno del server l'utente è identificato univocamente dal hash della chiave pubblica
- [] Login e registrazione devono essere un'unica operazione, il client deve essere all'oscuro del fatto che si stia registrando o loggando.

unione di due account
username + uuid server: due tabelle: hash uuid + username la chiave 
l altra tabelle 
autenticazione e registrazione sono la stessa.
salvattagio chaive pb: file binario, formato standard per salvare le chiavi - AES 128 - pc: password, telefono: pin, l impronta

token: hash nuova chiave public
firma digitale per l'autorizzazione del nuovo dispositivo