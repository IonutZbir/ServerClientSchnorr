# TODO

- [x] Modificare la fase di handshake: il client fa un richiesta di handshake, il server risponde poi con la lista dei gruppi crittografici. Il client verifica nella sua lista se i gruppi inviati dal server sono presenti e ne sceglie uno inviando poi al server il gruppo scelto. Nel caso in cui il client non abbia a disposizione nessun gruppo crittografico invia a server un messaggio NOK, chiudendo la connessione.
- [x] Ciascun account deve essere identificato a lato serever dall'username inserito dall'utente (uno qualsiasi) più un uuid. Il client, al momento della registrazione deve inviare al server, username, pk, e l'hash della chiave pubblica. All'interno del server l'utente è identificato univocamente dal hash della chiave pubblica
- [x] Login e registrazione devono essere un'unica operazione, il client deve essere all'oscuro del fatto che si stia registrando o loggando.
- [ ] La chiave publica deve essere salvata in un file binario, magari usando un formato standard per salvare le chiavi. Cifrare poi il file con AES 128, in tal caso l'utente deve inserire una password per decifrare il file. Sul telefono si può usare il pin o l'impronta. L'utente può anche decidere di non cifrare il file.
- [ ] Possibilità di unire due account, simile all'accoppiamento di un nuovo dispositivo. Ci deve essere una prefase in cui bisogna inserire l'uuid dell'account a cui si chiede di fare l'unione. In seguito c'è la fase di accettazione/firma da parte di uno del dispositivo collegato all'account.

token: hash nuova chiave pubblica
firma digitale per l'autorizzazione del nuovo dispositivo
