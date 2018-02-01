
                        ##############################
                        #           README           #
                        #                            #
                        #  Nume Proiect:Tema3 IOCLA  #
                        #  Creat de: Apostol Teodor  #
                        #        Grupa: 322CC        #
                        #    Deadline: 14.01.2018    #
                        #                            #
                        ##############################



Task 1:
	I. Functia main() - gasita la adresa 0x80489aa :
-> Apeleaza functia setbuf() din biblioteca <stdio.h> cu urmatoarele
argumente: setbuf(stdin, 0x0) = setbuf(FILE *filestream, char *buf).
Functia setbuf() in cazul asta, face citirea sa fie unbuffered.

-> Apeleaza functie setbuf() din nou, doar ca acum face ca afisarea
(la stdout) sa fie unbuffered.

-> Apeleaza mmap(addr, length, prot, flags, fd, offset) din biblioteca
<sys/mman.h> astfel incat aloca memorie la o adresa aleasa de catre
kernel (pentru ca addr = 0x0), de 0x400 = 1024 de octeti (= length).
Protectia pentru memoria alocata este Read + write (prot = 0x3),
file descriptor-ul (fd) e setat ca -1 (0xffffffff) si offset-ul este
0 (MAP_ANONYMOUS).
Cu alte cuvinte, se aloca o memorie de 1024 de octeti la o adresa ce
este aleasa de kernel si aceasta este returnata de functia mmap().

Adresa returnata este salvata in variabila globala (neinitializata
".bss") de la adresa 0x804a428 pe care o voi numi "adresa_aloc".

-> Apeleaza:
	II. Functia de la adresa 0x8048635. Aceasta functie are scopul de a
decripta mesajul de Welcome si optiunile dintre care utilizatorul va putea
alege ulterior, din acest motiv am numit-o "decrypt_options".

Functia va fi apelata de doua ori:
1. pentru decriptarea mesajului de Welcome din chenar. Acesta este salvat in
forma criptata intr-o variabila globala, la adresa 0x804a2c0.
O voi numi "string_welcome"

2. pentru a decripta optiunile pe care le are utilizatorul. Stringul cu aceste
optiuni este o variabila globala aflata la adresa: 0x804a340.
O voi numi "string_optiuni"

Implementare in pseudocod high-level ar fi:

decrypt_output(char message[], int len)
{
	int var = 0;
	char var2;
	while (var < len)
	{
		var2 = message[var] xor 0xaa; //170
		messsage[var] = var2;
		var ++;
	}
}
Decriptarea consta in a face xor inplace pe fiecare element al stringului a 
carui referinta a fost primita ca parametru, cu 0xaa.

-> Apeleaza:
	III. Functia de la adresa 0x8048871, pe care o voi numi "show_welcome"
care va afisa mesajul de Welcome in chenar (adica output-ul de la prima primul
apel al functiei decrypt_output).
O implementare in pseudocod high-level ar fi:

show_welcome()
{
	puts(string_welcome);
}

-> Apeleaza:
	IV. Functia de la adresa 0x8048883, pe care o voi numi "show_options"
care va afisa optiunile din care va putea alege utilizatorul pentru a avansa
in aplicatie.
O implementare in pseudocod high-level ar fi:

show_options()
{
	puts(string_optiuni);
}

-> Apeleaza:
	V. Functia de la adresa 0x804893a, pe care o voi numi "manage_options"
Aceasta functie va decide modul in care va continua programul in functie de
input-ul utilizatorului.
Daca utilizatorul introduce o valoare invalida (mai mare decat 5), unde 5
se stie ca este numarul optiunilor, functia va afisa mesajul:
"Unknown option." - mesaj ce se afla intr-o variabila globala, la adresa
0x8048ddf.
In cazul in care input-ul este egal cu 5, functia va inchide programul.
O implementare in pseudocod high-level ar fi:

manage_options()
{
	int var;
	scanf("%d", &var);
	if (var > 5)
	{
		//mai mare decat indexul ultimei optiuni
		puts("Unknown option.");
		return;
	}
	switch (var)
	{
	case 0:
	{
		read_serial();
		break;
	}
	case 1:
	{
		set_username();
		break;
	}
	case 2:
	{
		set_address();
		break;
	}
	case 3:
	{
		vault_key();
		break;
	}
	case 4:
	{
		magic_unlock();
		break;
	}
	case 5:
	{
		puts("Bye.");
		exit(1);
	}
	return;
}

Functia manage_options, pentru input-uri cuprinse intre 0 si 4 va apela la
randul ei alte functii. Numele acestor functii l-am scris in pseudocod, mai
departe voi detalia modul lor de functionare si adresa la care se gasesc.
Numele functiilor a fost ales intr-un mod intuitiv:

	VI. Functia "read_serial" se gaseste la adresa: 0x8048679
Functia va citi serial key-ul introdus de utilizator si il va verifica. In
functie de corectitudinea acestuia se va afisa mesajul "Correct!", aflat
intr-o variabila globala la adresa 0x8048d5e sau "Nope, try again.", aflat
la adresa 0x8048d67.

O implementare in pseudocod high-level:
read_serial()
{
	int v[32]; //aici vom salva serial key-ul
	int i;
	for (i = 0; i < 8; i ++)
	{
		v[i] = 0;
	}
	puts("Enter the valid serial: ");
	scanf("%32s", v);
	//"%32s" variabila globala la adresa: 0x8048d59

	if (check_serial(v) == 0)
	{
		puts("Nope, try again.");
		return;
	}
	puts("Correct!");
	return;
}

Pentru verificarea codului introdus, se apeleaza functia check_serial(), 
aflata la adresa: 0x8048a5d
In aceasta functie se realizeaza verificari pentru fiecare caracter.
Se folosesc operatii aritmetice si de asemenea functia ascii_hex, de la adresa
0x8048a29.
Functia ascii_hex transforma un numar in hexazecimal salvat in dl in felul
urmator (pe principiul temei 1):
Primeste numarul, si identifica intervalul in care se gaseste pe tabela ascii.
Daca este un numar care in ascii reprezinta un caracter cifra '0' - '9' atunci
va intoarce cifra convertita in hexazecimal, daca este o litera de la 'a' la
'f' va intoarce valoarea cifrei hex corespunzatoare in hex.
Dupa verificarea fiecarui caracter/ set de caractere, se decide daca registrul
eax va fi nul sau nenul (daca avem un caracter gresit, eax va fi nul, altfel
va fi nenul).
Rezultatul intors de check_serial() va fi 1 (corect) sau 0 (gresit) si astfel
se va decide mesajul afisat.

Pentru aflarea serial key-ului am parcurs verificarea pentru fiecare caracter
invers (de la cmp, de unde am luat valoarea) si am inversat calculele si
ordinea.

	VII. Functia set_username se afla la adresa: 0x80486ea
Functia afiseaza "Enter desired username: ", string aflat la adresa 0x8048d78,
aloca 20 de octeti pentru stringul in care va fi salvat user-ul si apoi se
realizeaza citirea.

Implementare in pseudocod high-level:
set_username()
{
	printf("Enter desired username: ");
	char user[20];
	scanf("%20s", user);
	return user;
}

	VIII. Functia set_address se afla la adresa: 0x8048710
Functioneaza pe acelasi principiu ca functia set_username()

Implementare in pseudocod high-level:
set_address()
{
	printf("Enter desired address: ");
	char addr[16];
	scanf("%20s", addr);
	return addr;
} 
"Enter desired address " la adresa: 0x8048d96

	IX. Functia vault_key se afla la adresa: 0x8048736
Aceasta citeste 
Implementare in pseudocod high-level:
vault_key()
{
	int var;
	size_t count = 0x18;
	int *buf = &var;
	int fd = 0;
	read(fd, buf, count);
}
Numele fd, buf, count, impreuna cu tipurile le-am dat din pagina de manual
a functiei read(), functie din biblioteca: <unistd.h>. Aceasta incearca sa
citeasca count octeti din fd (file descriptor) dat ca parametru si salveaza
in buf ce s-a citit.

	X. Functia magic_unlock se afla la adresa: 0x804874e
La inceputul functiei se va verifica daca cele trei variabile globale sunt
nenule. Cele 3 variabile sunt aflate la adresele: 0x804a298, 0x804a29c,
0x804a2a0.
Daca toate cele 3 variabile sunt diferite de 0, atunci se citeste cu functia
read 0x400, adica 1024 de caractere, pe stiva. read(0, ebp-0x401, 0x400).
Dupa ce a fost citit stringul, se adauga terminatorul.
Variabila globala de la adresa 0x804a428, o voi numi "adresa_aloc"
este decriptaa cu ajutorul functiei decrypt_output, explicata
mai sus.
Se apeleaza functia sum, de la adresa: 0x80485eb.
Aceasta functie verifica daca suma tuturor elementelor din sirul citit mai
sus este egala cu 0x12345.
Daca input-ul a trecut si de aceasta verificare se trece mai departe la
verificarea numelui. Se verifica cu functia strstr() daca sirul citit contine
"Teodor" si apoi daca contine "Apostol". Dupa ce am trecut de aceasta ultima
verificare, functia va folosi functia mprotect(addr, len, prot) =
mprotect(adresa_aloc, 0x400, 0x5), cu alte cuvinte vom da drepturi de executie
functiei ce se afla la adresa data ca parametru.

In cazul in care nu am trecut de vreuna dintre verificari se va afisa mesajul
"Vault is still locked.", aflat la adresa 0x8048dae.
