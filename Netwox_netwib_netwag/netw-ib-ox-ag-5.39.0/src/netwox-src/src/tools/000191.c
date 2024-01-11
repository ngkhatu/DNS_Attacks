/*
                                  NETWOX
                             Network toolbox
                Copyright(c) 1999-2012 Laurent CONSTANTIN
                      http://ntwox.sourceforge.net/
                        laurentconstantin@free.fr
                                  -----

  This file is part of Netwox.

  Netwox is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License version 3
  as published by the Free Software Foundation.

  Netwox is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details (http://www.gnu.org/).

------------------------------------------------------------------------
*/

/*-------------------------------------------------------------*/
#include "../netwox.h"

/*-------------------------------------------------------------*/
netwib_conststring t000191_description[] = {
  "This tool generates one or several passwords.",
  "",
  "Choosing a password is a complex task: it has to be random, but also",
  "easy to remember (otherwise people write it down).",
  "When choosing one password, we can use a mnemotechnic sentence (tiap =",
  "this is a password) or mix words (house + 2,E: = h2o,uEs:e).",
  "When a program has to generate passwords (for example for all users of",
  "an enterprise), the main problem is where to find/store sentences and",
  "words. An attacker knowing those lists will find passwords using a",
  "brute force attack.",
  "",
  "This password generator uses another method. It generates passwords",
  "composed of the two first letters of images. An image is an easy to",
  "remember word. For example:",
  "  netwox 191 --numimages 5 --lang-english",
  "    password: soasprsivo",
  "    images: SOap AStronaut PRofessor SIx VOlcano",
  "So, user only have to remember those 5 images: soap, astronaut,",
  "professor, 6 and volcano. Those images are easy to draw or represent",
  "ideas easy to draw. For higher security, choose 5 or more images.",
  "",
  "In order to provide complex passwords, variations of generated",
  "password are proposed. With the last example:",
  "  variation1: soaspr2ivo. In this case, one letter has changed",
  "                          (s replaced by 2)",
  "  variation2: soAsprs1vo. In this case, two letters have changed",
  "                          (a replaced by A, and i by 1)",
  "So, you can use soAsprs1vo instead of soasprsivo.",
  "",
  "Finally, parameter --pronounceable generates pronounceable passwords.",
  "For example: netwox 191 --pronounceable --maxsyllables 3",
  NETWOX_DESC_toolpriv_none,
  NULL
};
netwox_toolarg t000191_args[] = {
  NETWOX_TOOLARG_OPT_UINT32('n', "numpassword",
                            "number of passwords to generate", "1"),
  NETWOX_TOOLARG_OPT_UINT32('i', "numimages", "number of images in passwords",
                            "5"),
  NETWOX_TOOLARG_RADIO1_SET('E', "lang-english", "use English words"),
  NETWOX_TOOLARG_RADIO1('F', "lang-french", "use French words"),
  NETWOX_TOOLARG_RADIO1('S', "lang-spanish", "use Spanish words"),
  NETWOX_TOOLARG_OPT_BOOL('p', "pronounceable",
                          "generate pronounceable passwords", NULL),
  NETWOX_TOOLARG_OPT_UINT32('m', "maxsyllables",
                            "max syllables in pronounceable passwords", NULL),
  NETWOX_TOOLARG_OPT_BUF('a', "allowedcharvar",
                         "allowed characters for variations",
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@|!()[]{}/$+&^*"),
  NETWOX_TOOLARG_END
};
netwox_tooltreenodetype t000191_nodes[] = {
  NETWOX_TOOLTREENODETYPE_NOTNET,
  NETWOX_TOOLTREENODETYPE_BRUTEFORCE,
  NETWOX_TOOLTREENODETYPE_END
};
netwox_tool_info t000191_info = {
  "Generate a password (English, French, Spanish)",
  t000191_description,
  NULL,
  t000191_args,
  t000191_nodes,
};

/*-------------------------------------------------------------*/
/* English */
netwox_passwordgeneword t000191_en_words[] = {
  /* This is a list of words whose 2 first letters are unique.
     They should be easy to remember/draw. */
  "above",
  "acid",
  "address",
  "aerosol",
  "africa",
  "agent",
  "airplane",
  "alphabet",
  "ampersand",
  "angel",
  "apple",
  "array",
  "astronaut",
  "atom",
  "augment",
  "award",
  "axe",
  "baby",
  "bed",
  "bicycle",
  "black",
  "book",
  "brake",
  "bus",
  "bye",
  "cat",
  "cdrom",
  "centimeter",
  "chair",
  "circle",
  "clock",
  "computer",
  "cross",
  "cube",
  "cyclone",
  "date",
  "desk",
  "diploma",
  "dog",
  "dragon",
  "duck",
  "ear",
  "egg",
  "eight",
  "elephant",
  "empty",
  "engine",
  "equal",
  "eraser",
  "europe",
  "exclamation",
  "eye",
  "face",
  "fence",
  "five",
  "fly",
  "four",
  "france",
  "garden",
  "gentleman",
  "ghost",
  "gift",
  "glove",
  "gold",
  "grass",
  "guitar",
  "hand",
  "head",
  "hill",
  "horse",
  "human",
  "iceberg",
  "idea",
  "image",
  "ink",
  "iron",
  "island",
  "italic",
  "jail",
  "jewel",
  "job",
  "journal",
  "key",
  "kitchen",
  "klaxon",
  "knife",
  "labyrinth",
  "leg",
  "list",
  "love",
  "man",
  "meter",
  "micro",
  "mouse",
  "muscle",
  "name",
  "network",
  "nine",
  "node",
  "oasis",
  "ocean",
  "office",
  "oil",
  "ok",
  "one",
  "open",
  "orange",
  "out",
  "oval",
  "oxygen",
  "ozone",
  "paper",
  "pen",
  "phone",
  "piano",
  "planet",
  "pocket",
  "price",
  "professor",
  "pull",
  "pyramid",
  "queen",
  "radio",
  "red",
  "right",
  "road",
  "ruin",
  "salt",
  "screen",
  "seven",
  "shoe",
  "six",
  "sky",
  "sleep",
  "smile",
  "snow",
  "soap",
  "spark",
  "square",
  "star",
  "sun",
  "switch",
  "table",
  "ten",
  "three",
  "ticket",
  "tomato",
  "train",
  "tunnel",
  "two",
  "umbrella",
  "under",
  "up",
  "vapor",
  "vector",
  "video",
  "volcano",
  "wagon",
  "web",
  "wheel",
  "window",
  "woman",
  "wrist",
  "yacht",
  "year",
  "young",
  "zero",
  "zip",
  "zoo",
  NULL
};
netwox_passwordgeneword t000191_en_vowels[] = {
  /* This is a list of vowels (except y). They can be obtained
     with this script :
       cat words.txt | sed 's/[^aeiou]/_/g' | tr '_' '\012' |\
       sort -u | while read l
       do
         n=`grep "$l" words.txt | wc -l`
         echo "$l $n"
       done
     Only most frequents are used.
  */
  "ai",
  "au",
  "ee",
  "ei",
  "eu",
  "ie",
  "oo",
  "ou",
  "a",
  "e",
  "i",
  "o",
  "u",
  NULL
};
netwox_passwordgeneword t000191_en_consonant_begin[] = {
  /* This is a list of consonants beginning a word. They can be obtained
     with this script :
       cat words.txt | sed 's/[aeiou].*$//' | sort -u | while read l
       do
         n=`grep "^$l" words.txt | wc -l`
         echo "$l $n"
       done
     Only most frequents are used.
  */
  "chl",
  "chr",
  "sch",
  "scl",
  "scr",
  "sph",
  "spl",
  "spr",
  "squ",
  "str",
  "thr",
  "thw",
  "bl",
  "br",
  "ch",
  "cl",
  "cr",
  "dr",
  "dw",
  "fl",
  "fr",
  "gl",
  "gn",
  "gr",
  "kl",
  "kn",
  "kr",
  "pl",
  "pr",
  "ps",
  "qu",
  "sc",
  "sf",
  "sh",
  "sk",
  "sl",
  "sm",
  "sn",
  "sp",
  "st",
  "sw",
  "th",
  "tr",
  "ts",
  "tw",
  "wh",
  "wr",
  "b",
  "c",
  "d",
  "f",
  "g",
  "h",
  "j",
  "k",
  "l",
  "m",
  "n",
  "p",
  "r",
  "s",
  "t",
  "v",
  "w",
  "x",
  "y",
  "z",
  NULL
};
netwox_passwordgeneword t000191_en_consonant_end[] = {
  /* This is a list of consonants ending a word. They can be obtained
     with this script :
       cat words.txt | sed 's/^.*[aeiou]//' | sort -u | while read l
       do
         n=`grep "$l$" words.txt | wc -l`
         echo "$l $n"
       done
     Only most frequents are used.
  */
  "nst",
  "ff",
  "ld",
  "ll",
  "lm",
  "lt",
  "nc",
  "ng",
  "nt",
  "nx",
  "pt",
  "rb",
  "rc",
  "rd",
  "rf",
  "rg",
  "rk",
  "rl",
  "rm",
  "rn",
  "rp",
  "rs",
  "rt",
  "sk",
  "sm",
  "sp",
  "ss",
  "st",
  "wn",
  "wt",
  "xt",
  "b",
  "c",
  "d",
  "f",
  "g",
  "j",
  "k",
  "l",
  "m",
  "n",
  "p",
  "r",
  "s",
  "t",
  "v",
  "w",
  "x",
  "z",
  NULL
};

/*-------------------------------------------------------------*/
/* French */
netwox_passwordgeneword t000191_fr_words[] = {
  "abricot",
  "accordeon",
  "adhesif",
  "aeroport",
  "affiche",
  "agrafe",
  "aigle",
  "alarme",
  "amande",
  "ane",
  "apache",
  "aquarium",
  "arbre",
  "astre",
  "atome",
  "auberge",
  "avion",
  "axe",
  "bateau",
  "bd",
  "bebe",
  "biberon",
  "ble",
  "bonbon",
  "briquet",
  "buche",
  "carotte",
  "cdrom",
  "cerise",
  "chat",
  "cigare",
  "clavier",
  "coq",
  "crabe",
  "cube",
  "cygne",
  "damier",
  "dent",
  "disque",
  "doigt",
  "drapeau",
  "dune",
  "dynamite",
  "eau",
  "echelle",
  "eglise",
  "elephant",
  "email",
  "encrier",
  "epee",
  "equerre",
  "escargot",
  "etoile",
  "euros",
  "evier",
  "extincteur",
  "faucon",
  "fenetre",
  "ficelle",
  "fleur",
  "fourmi",
  "fraise",
  "fusil",
  "gateau",
  "genou",
  "girafe",
  "glace",
  "gorille",
  "grillon",
  "guirlande",
  "haie",
  "helice",
  "hibou",
  "hotel",
  "huit",
  "hydravion",
  "iceberg",
  "idee",
  "igloo",
  "ile",
  "image",
  "indien",
  "ion",
  "issue",
  "ivoire",
  "jambe",
  "jeton",
  "jongleur",
  "jupe",
  "kangourou",
  "kepi",
  "kiosque",
  "klaxon",
  "lacet",
  "lentille",
  "livre",
  "losange",
  "lunette",
  "lynx",
  "marteau",
  "medaille",
  "micro",
  "moto",
  "mur",
  "navire",
  "nez",
  "nid",
  "note",
  "nuage",
  "oasis",
  "obus",
  "octet",
  "odeur",
  "oeil",
  "oiseau",
  "ok",
  "olive",
  "ombre",
  "onze",
  "orange",
  "os",
  "otarie",
  "ours",
  "ovale",
  "oxygene",
  "ozone",
  "panier",
  "pelle",
  "photo",
  "piano",
  "plongeur",
  "pneu",
  "pomme",
  "prairie",
  "puits",
  "pyramide",
  "question",
  "rame",
  "rectangle",
  "rhum",
  "riviere",
  "robot",
  "ruine",
  "sapin",
  "scie",
  "selle",
  "sifflet",
  "ski",
  "smoking",
  "souris",
  "sphere",
  "squelette",
  "stylo",
  "sucre",
  "systeme",
  "table",
  "television",
  "thon",
  "ticket",
  "tortue",
  "train",
  "tuile",
  "tv",
  "tympan",
  "un",
  "urne",
  "usine",
  "vache",
  "velo",
  "vin",
  "voiture",
  "vulnerabilite",
  "wagon",
  "whisky",
  "xylophone",
  "yacht",
  "yeux",
  "yoyo",
  "zebre",
  "zoom",
  NULL
};
netwox_passwordgeneword t000191_fr_vowels[] = {
  "eau",
  "oui",
  "ai",
  "au",
  "ei",
  "eo",
  "eu",
  "io",
  "oi",
  "ou",
  "ui",
  "a",
  "e",
  "i",
  "o",
  "u",
  NULL
};
netwox_passwordgeneword t000191_fr_consonant_begin[] = {
  "chl",
  "chr",
  "sch",
  "scr",
  "sph",
  "spl",
  "spr",
  "bl",
  "br",
  "ch",
  "cl",
  "cr",
  "dr",
  "fl",
  "fr",
  "gl",
  "gn",
  "gr",
  "kl",
  "kr",
  "pl",
  "pn",
  "pr",
  "ps",
  "qu",
  "sc",
  "sl",
  "sm",
  "sp",
  "st",
  "tr",
  "vr",
  "b",
  "c",
  "d",
  "f",
  "g",
  "h",
  "j",
  "k",
  "l",
  "m",
  "n",
  "p",
  "r",
  "s",
  "t",
  "v",
  "w",
  "x",
  "y",
  "z",
  NULL
};
netwox_passwordgeneword t000191_fr_consonant_end[] = {
  "b",
  "c",
  "d",
  "f",
  "k",
  "l",
  "m",
  "n",
  "p",
  "r",
  "s",
  "t",
  "v",
  "w",
  "x",
  "z",
  NULL
};

/*-------------------------------------------------------------*/
/* Spanish */
netwox_passwordgeneword t000191_sp_words[] = {
  "abeto",
  "aceite",
  "adicion",
  "aeropuerto",
  "africa",
  "agua",
  "ahorcar",
  "ajedrez",
  "alfombra",
  "amarillo",
  "andar",
  "arco",
  "aspirador",
  "atun",
  "autobus",
  "avion",
  "ayer",
  "azul",
  "barco",
  "bebe",
  "bicicleta",
  "blanco",
  "bosque",
  "brazo",
  "bufanda",
  "caballo",
  "cdrom",
  "cero",
  "chocolate",
  "cinco",
  "clave",
  "coche",
  "cruz",
  "cuchillo",
  "dardo",
  "dedo",
  "diez",
  "dos",
  "dragon",
  "ducha",
  "eclipse",
  "elefante",
  "ensalada",
  "eriso",
  "esqui",
  "etiqueta",
  "europa",
  "everest",
  "extinto",
  "faro",
  "fiesta",
  "flama",
  "folio",
  "fresa",
  "fuego",
  "gato",
  "golf",
  "grapa",
  "gusano",
  "hada",
  "hermano",
  "hijo",
  "hotel",
  "huevo",
  "iglesia",
  "ingles",
  "isla",
  "italia",
  "izquierda",
  "jamon",
  "jefe",
  "jirafa",
  "joya",
  "juego",
  "karate",
  "kilogramo",
  "labio",
  "leche",
  "limon",
  "lluvia",
  "lobo",
  "luna",
  "manzana",
  "medallas",
  "mil",
  "mono",
  "museo",
  "naranja",
  "negro",
  "nieve",
  "norte",
  "nube",
  "oasis",
  "ocho",
  "oficina",
  "ojo",
  "ok",
  "oliva",
  "once",
  "oro",
  "oso",
  "otono",
  "ovalo",
  "oxigeno",
  "ozono",
  "paloma",
  "pez",
  "pie",
  "playa",
  "policia",
  "princesa",
  "puente",
  "quatro",
  "radio",
  "reloj",
  "rinoceronte",
  "rojo",
  "rueda",
  "sal",
  "seis",
  "siete",
  "sol",
  "sur",
  "taxi",
  "telephono",
  "tierra",
  "toro",
  "tres",
  "tubo",
  "ultimo",
  "uno",
  "vaca",
  "verde",
  "vino",
  "volante",
  "vuelta",
  "yate",
  "zapato",
  "zorro",
  "zumo",
  NULL
};
netwox_passwordgeneword t000191_sp_vowels[] = {
  "a",
  "aa",
  "ae",
  "ai",
  "ao",
  "au",
  "e",
  "ea",
  "ee",
  "ei",
  "eo",
  "eu",
  "i",
  "ia",
  "ie",
  "io",
  "iu",
  "o",
  "oa",
  "oe",
  "oi",
  "oo",
  "u",
  "ua",
  "ue",
  "uea",
  "ui",
  "uia",
  "uo",
  NULL
};
netwox_passwordgeneword t000191_sp_consonant_begin[] = {
  "b",
  "bl",
  "br",
  "c",
  "ch",
  "cl",
  "cr",
  "d",
  "dr",
  "f",
  "fl",
  "fr",
  "g",
  "gl",
  "gr",
  "j",
  "l",
  "ll",
  "m",
  "n",
  "p",
  "pl",
  "pr",
  "q",
  "r",
  "s",
  "t",
  "tr",
  "v",
  "y",
  "z",
  NULL
};
netwox_passwordgeneword t000191_sp_consonant_end[] = {
  "d",
  "l",
  "m",
  "n",
  "r",
  "s",
  "t",
  "x",
  "z",
  NULL
};

/*-------------------------------------------------------------*/
netwib_err t000191_core(int argc, char *argv[])
{
  netwox_arg *parg;
  netwib_uint32 numpassword, numimages, maxsyllables;
  netwib_bool pronounceable;
  netwib_buf allowedcharvar;
  netwib_char c;

  /* obtain parameters */
  netwib_er(netwox_arg_init(argc, argv, &t000191_info, &parg));
  netwib_er(netwox_arg_uint32(parg, 'n', &numpassword));
  netwib_er(netwox_arg_uint32(parg, 'i', &numimages));
  netwib_er(netwox_arg_bool(parg, 'p', &pronounceable));
  netwib_er(netwox_arg_uint32(parg, 'm', &maxsyllables));
  netwib_er(netwox_arg_buf(parg, 'a', &allowedcharvar));
  netwib_er(netwox_arg_radio1(parg, &c));

  /* generate */
  switch(c) {
  case 'E' :
    netwib_er(netwox_passwordgene(numpassword, numimages, pronounceable,
                                  maxsyllables, t000191_en_words,
                                  &allowedcharvar, t000191_en_vowels,
                                  t000191_en_consonant_begin,
                                  t000191_en_consonant_end));
    break;
  case 'F' :
    netwib_er(netwox_passwordgene(numpassword, numimages, pronounceable,
                                  maxsyllables, t000191_fr_words,
                                  &allowedcharvar, t000191_fr_vowels,
                                  t000191_fr_consonant_begin,
                                  t000191_fr_consonant_end));
    break;
  case 'S' :
    netwib_er(netwox_passwordgene(numpassword, numimages, pronounceable,
                                  maxsyllables, t000191_sp_words,
                                  &allowedcharvar, t000191_sp_vowels,
                                  t000191_sp_consonant_begin,
                                  t000191_sp_consonant_end));
    break;
  }

  /* close */
  netwib_er(netwox_arg_close(&parg));

  return(NETWIB_ERR_OK);
}