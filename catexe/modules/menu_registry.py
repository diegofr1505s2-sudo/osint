"""Registre déclaratif des modules et des mots-clés de recherche."""


def build_sections(learn_count: int = 23, discord: str = "https://discord.gg/RWYAPZ8Qbp"):
    """Construit les sections du menu sans dépendre de l'application."""
    return [
    ("RECON IDENTITÉ", [
        ("mod_social", "👥 Lookup réseaux sociaux", "17 plateformes · fiches", "Fiche détaillée d'un pseudo sur GitHub (emails des commits, clés SSH), Reddit (heures d'activité → fuseau), TikTok, Instagram, YouTube, Bluesky, Mastodon, Telegram, Steam, Roblox, Chess.com, Lichess, GitLab, Hacker News, Keybase, Linktree, Docker Hub.\n\nInspiré de Sherlock / Maigret / Osintgram. Une fiche par page (n / p)."),
        ("mod_wmn", "🌐 Pseudo sur 600+ sites", "WhatsMyName", "Teste un pseudo sur plus de 600 sites avec la base WhatsMyName (celle utilisée par les pros de l'OSINT), mise à jour automatiquement.\n\nRésultats par pages + page HTML cliquable."),
        ("mod_person", "🧍 Recherche de personne", "emails · pseudos · annuaires", "Prénom + nom → adresses email probables (testées via Gravatar), pseudos probables, et toutes les recherches prêtes : LinkedIn, Facebook, Pages Blanches, Copains d'avant, dirigeants d'entreprise, PDF…"),
        ("mod_discord", "💬 Discord lookup", "invitation · ID · widget", "Analyse une invitation Discord (serveur, ID, membres, créateur de l'invitation), la date de n'importe quel ID, un compte (avec token) ou les membres en ligne d'un serveur."),
        ("mod_user", "👤 Pseudos", "95 sites", "Teste un pseudo sur 95 sites (réseaux, jeux, dev, créa…) en parallèle, avec ses variantes (_ . -).\n\nTu donnes : un pseudo.\nTu obtiens : la liste des comptes trouvés, un niveau d'exposition et une checklist IA."),
        ("mod_prevname", "⏳ Prevname", "anciens pseudos", "Retrouve les anciens pseudos d'un compte : Steam, Roblox, Minecraft, X, GitHub, Bluesky (historique complet), Discord (ID), 36 sites qui redirigent les anciens noms et 57 plateformes dans les archives web."),
        ("mod_email", "📧 Email", "fuites · Gravatar", "Vérifie une adresse : fuites de données connues, avatar Gravatar, fournisseur, adresse jetable ou non, sécurité du domaine (SPF/DMARC)."),
        ("mod_holehe", "📬 Email → comptes", "Holehe · 120 sites", "Teste sur ~120 sites (Instagram, Spotify, Amazon, Discord…) si un compte existe avec un email, comme l'outil Holehe, sans prévenir la personne. + lien Epieos."),
        ("mod_breaches", "💧 Fuites d'un site", "Have I Been Pwned", "Un site ou un service a-t-il déjà été piraté ? Date de la fuite, nombre de comptes, données exposées (emails, mots de passe, adresses…), d'après la base publique Have I Been Pwned."),
        ("mod_pwned", "🔑 Fuite de mot de passe", "sans l'envoyer", "Vérifie si un mot de passe est dans les 900 millions de mots de passe fuités, sans jamais l'envoyer (seuls 5 caractères de son empreinte partent).\n\nDonne aussi sa force et le temps pour le casser."),
        ("mod_phone", "📱 Téléphone", "pays · opérateur", "Analyse un numéro : pays, type (mobile/fixe), opérateur d'origine, fuseau horaire, liens de recherche."),
        ("mod_bodacc", "📰 Annonces légales (BODACC)", "entreprises · dirigeants", "Créations, ventes, changements de dirigeant, redressements et liquidations d'entreprises françaises, depuis le bulletin officiel (BODACC)."),
        ("mod_iban", "🏦 IBAN", "clé · pays · banque", "Vérifie un IBAN avant un virement : clé de contrôle, pays, banque, guichet. Contre les faux RIB."),
        ("mod_vin", "🚗 Véhicule (VIN)", "constructeur · année · modèle", "Décode le numéro de série d'un véhicule : constructeur, pays, année, modèle, énergie. Pour vérifier une annonce d'occasion."),
        ("mod_crypto", "₿  Crypto", "solde · transactions", "Adresse Bitcoin / Ethereum : solde, nombre de transactions, première et dernière activité."),
        ("mod_ids", "🆔 Décodeur d'ID & dates", "date cachée d'un lien", "Retrouve la date exacte cachée dans un lien ou un identifiant : vidéo TikTok, post X/Instagram/Threads/LinkedIn/Bluesky/Mastodon, ID Discord, timestamps Unix/Windows/Apple, UUID…\n\nMarche même si la date est masquée ou le post supprimé."),
    ]),
    ("IMAGE & GEOINT", [
        ("mod_maplink", "📎 Lien de carte → coordonnées", "Google Maps · Waze · OSM…", "Colle un lien Google Maps (même court), Apple Plans, Waze, OpenStreetMap, Bing, Yandex ou Here : l'outil sort les coordonnées, l'adresse, tous les formats et ouvre le lieu dans 8 autres cartes (Earth, Mapillary, Géoportail, Peakvisor…)."),
        ("mod_photobatch", "👣 Lot de photos → trajet", "carte + chronologie", "Donne un dossier de photos : l'outil lit les dates et GPS de toutes les photos, les range dans l'ordre, trace le trajet sur une carte, liste les appareils utilisés et exporte la chronologie pour Excel."),
        ("mod_imgcompare", "🪞 Comparer deux images", "même photo ? retouche ?", "Dit si deux images sont la même (recadrée, recompressée, retouchée) grâce à 3 empreintes visuelles, et crée une carte des différences. Pratique pour trouver l'original et repérer une retouche."),
        ("mod_img2gps", "📌 Image → coordonnées", "GPS · IA locale", "Tu donnes une image (fichier ou lien), l'outil sort directement ses coordonnées : GPS caché dans le fichier, sinon estimation par l'IA locale GeoCLIP (top 5) et l'IA de vision, avec adresse, formats DMS/UTM et carte."),
        ("mod_revimg", "🔎 Recherche inversée d'image", "Lens · Yandex · TinEye · Bing", "Retrouve où une image apparaît sur internet (original, première publication, copies) sur 6 moteurs à la fois : Google Lens, Yandex, TinEye, Bing, SauceNAO, Baidu."),
        ("mod_geo", "📍 Géoloc photo", "100 % auto par l'IA", "Trouve où une photo a été prise et où se tenait le photographe : GPS caché → IA GeoCLIP → IA de vision qui repère les monuments → triangulation → heure par les ombres.\n\nTu donnes juste la photo."),
        ("mod_vidinfo", "📼 Vidéo en ligne : date", "YouTube · TikTok · miniatures", "Date exacte de mise en ligne d'une vidéo YouTube / Shorts / TikTok, chaîne, vues, mots-clés cachés, et miniatures prêtes pour la recherche inversée (comme InVID / YouTube DataViewer) : démasque les vieilles vidéos republiées."),
        ("mod_video", "🎬 Vidéo → images", "images + GPS caché", "Découpe une vidéo en images (planche contact) pour la géoloc ou la recherche de logo, et lit ses métadonnées cachées : date, téléphone, position GPS des vidéos iPhone/Android."),
        ("mod_logo", "🔖 Recherche de logo", "marque · image inversée", "Identifie une marque à partir d'un logo (IA locale), donne sa fiche, lance la recherche inversée (Google Lens, Bing, TinEye) et calcule le hash favicon Shodan d'un site."),
        ("mod_meta", "🧾 Métadonnées", "auteur · GPS · nettoyage", "Lit les métadonnées d'une photo, d'un PDF ou d'un document Office (auteur, appareil, GPS, logiciel, dates) et peut créer une copie nettoyée."),
        ("mod_ela", "🔬 Retouche ?", "analyse ELA", "Cherche les retouches dans une image : analyse ELA, qualité JPEG, empreinte perceptuelle."),
        ("mod_sun", "🌞 Ombres & soleil", "heure / lieu d'une photo", "Chronolocalisation : l'heure d'une photo grâce aux ombres, les zones possibles sur Terre, ou la course du soleil d'un lieu."),
        ("mod_weather", "☔ Météo passée", "vérifier une photo", "Météo heure par heure d'un lieu à une date passée : vérifie si une photo (pluie, ciel, neige) colle avec la date annoncée."),
        ("mod_webcams", "📹 Webcams d'un lieu", "Windy · vérif météo", "Webcams publiques officielles autour d'un lieu (météo, tourisme, stations, ports) avec carte, aperçus et time-lapse de la journée, pour vérifier un lieu ou la météo d'une photo."),
        ("mod_place", "🌍 Infos d'un lieu", "adresse · UTM · 12 cartes", "Toutes les infos d'un point : adresse, coordonnées dans tous les formats, altitude, et 12 cartes (Street View, Earth 3D, Mapillary, satellite…)."),
        ("mod_satellite", "📡 Satellite d'avant", "historique depuis 2014", "Compare les images satellite d'un lieu sur ~200 dates depuis 2014 : constructions, démolitions, travaux, véhicules garés…"),
        ("mod_bearing", "📏 Distance · horizon", "azimut · visibilité", "Distance et direction entre 2 points, point à X km dans une direction, distance de l'horizon, et si un sommet ou une tour est visible malgré la courbure de la Terre."),
        ("mod_clues", "🧩 Recherche par indices", "trouver le lieu sur la carte", "Combine des indices vus sur une photo (église + pharmacie + arrêt de bus…) pour trouver tous les endroits d'une zone où ils sont proches."),
        ("mod_planes", "🛫 Avions", "ADS-B en direct", "Avions en vol autour d'un point, en direct (dont les vols militaires visibles), avec carte."),
    ]),
    ("INFRA / WEB", [
        ("mod_iplookup", "🧭 IP lookup", "géo · VPN · Tor · ports", "Tout sur une IP ou un domaine : pays, ville, opérateur, ASN, reverse DNS, détection VPN / proxy / datacenter / Tor, ports ouverts et failles (Shodan InternetDB), autres sites sur la même IP, contact abus, carte.\n\n7 sources interrogées en même temps."),
        ("mod_domain", "🔭 Domaine / IP", "DNS · SSL · ports · CVE", "Audit d'un domaine ou d'une IP : DNS, sous-domaines, certificat, ports ouverts, failles connues, technologies, en-têtes de sécurité, rapport IA."),
        ("mod_harvest", "🌾 Récolte d'un domaine", "façon theHarvester", "Sous-domaines, emails, serveurs mail et personnes (Hunter) d'un domaine, depuis les certificats SSL, HackerTarget, CertSpotter et les pages du site."),
        ("mod_urlscan", "📸 URLScan.io", "capture · IP · verdict", "Voir un site sans le visiter : historique des scans publics, nouveau scan avec capture d'écran, IP, serveur, domaines contactés et verdict."),
        ("mod_wayurls", "🗃 Fichiers archivés", "Wayback · PDF · sauvegardes", "Liste les fichiers et pages d'un domaine gardés par la Wayback Machine : documents, sauvegardes oubliées, pages supprimées. Export CSV."),
        ("mod_mac", "🔌 Adresse MAC", "fabricant de l'appareil", "Trouve le fabricant d'un appareil à partir de son adresse MAC et dit si l'adresse est aléatoire."),
        ("mod_link", "🔗 Analyse de lien", "anti-phishing", "Avant de cliquer : suit les redirections, compare au vrai site, âge du domaine, signaux de phishing."),
        ("mod_headers", "📨 En-têtes d'email", "phishing · origine", "Analyse un email suspect : trajet des serveurs, IP et pays d'origine, SPF/DKIM/DMARC, faux expéditeur, domaine tout neuf → verdict."),
        ("mod_extract", "🧲 Extracteur d'indices", "page · fichier · texte", "Sort automatiquement les emails, téléphones, réseaux sociaux, IP, cryptos, IBAN, identifiants Google Analytics, clés exposées et coordonnées d'une page web, d'un fichier ou d'un texte."),
        ("mod_archive", "📚 Archives d'une page", "Wayback Machine", "Retrouve les anciennes versions d'une page ou toutes les pages archivées d'un site (contacts effacés, anciens documents…)."),
        ("mod_net", "🌐 Réseau", "IP · ASN · MAC", "Ton IP publique vue par les sites, propriétaire et plage d'une IP, opérateur d'un ASN, fabricant d'un appareil d'après son adresse MAC."),
        ("mod_dorks", "🔍 Dorks", "Google avancé", "Génère des recherches Google avancées (fichiers exposés, pages d'admin, fuites, profils) pour un domaine ou un pseudo."),
        ("mod_prosrc", "🗂 Sources pro", "Censys · Hunter · IntelX…", "Prépare et ouvre les sources pros adaptées à ta cible : Censys, Hunter, Epieos, Intelligence X, DeHashed, SecurityTrails, GreyNoise, BuiltWith, OSINT Framework, Bellingcat."),
    ]),
    ("CTF / ANALYSE", [
        ("mod_decode", "🔐 Décodeur", "mode magique", "Décode automatiquement Base64, hexa, binaire, Morse, ROT13, JWT, URL… même empilés les uns dans les autres. Encode aussi."),
        ("mod_toolbox", "🧰 Boîte à outils", "hors ligne", "Stéganographie (message caché dans une image, données après la fin du fichier), strings d'un fichier / .exe, calculateur CIDR, convertisseur de timestamps, générateur de mots de passe, convertisseur de coordonnées. Tout tourne sur ton PC."),
        ("mod_hash", "🔢 Hash & fichier", "vrai type · réputation", "Empreintes d'un fichier, détection des extensions trompeuses (facture.pdf.exe), réputation (CIRCL, VirusTotal), identification d'un hash."),
    ]),
    ("APPRENDRE", [
        ("mod_learn", "🎓 Apprendre à coder", f"{learn_count} langages · prof IA", "Apprends à programmer et à créer tes propres outils, sans limite : Python, JavaScript, HTML/CSS, C, C++, C#, Java, Rust, Go, PHP, SQL, Bash, PowerShell, Lua…\n\n"
         "Cours pas à pas, sujets libres, exercices corrigés (ton code est exécuté puis corrigé par l'IA), prof IA, et un parcours pour coder ton propre outil OSINT jusqu'au .exe."),
    ]),
    ("BUSINESS", [
        ("mod_biz", "🏢 Entreprises", "registre + Pages Jaunes", "Registre officiel des entreprises françaises : SIREN, dirigeants, effectif, adresse, état, liens Pappers / Pages Jaunes, analyse IA."),
    ]),
    ("ANONYMAT", [
        ("mod_anon", "🧅 Anonymat", "Tor · changer d'IP · navigateur", "Réduit ce que les sites voient de toi : test d'exposition (IP réelle vs IP via Tor), changement d'IP à la demande (nouveau circuit Tor), ouverture de Tor Browser ou Firefox sur Tor, et tests de fuites WebRTC / DNS.\n\nCe n'est pas l'anonymat total : la connexion à un compte perso te reconnaît quand même."),
    ]),
    ("CAT.EXE", [
        ("mod_diagnostics", "🧪 Diagnostic système", "Python · dépendances · outils", "Vérifie localement Python, les modules, Ollama, FFmpeg et Playwright sans envoyer de données."),
        ("mod_cyber_catalog", "🛡️ Catalogue cyber", "outils · filtres · risques", "Catalogue local issu de hacking-ethique : recherche, catégories, plateformes, licences et niveaux de risque. Les commandes sont affichées mais jamais exécutées automatiquement."),
        ("mod_graph", "🧬 Graphe d'enquête", "façon Obsidian · fenêtre", "Une fenêtre à part qui dessine ton enquête en toile : pseudos, comptes, emails, IP, lieux… reliés entre eux.\n\nChaque module que tu lances l'alimente tout seul, en direct. Tu peux ajouter des éléments, les relier, mettre des notes, chercher, filtrer par type et exporter en image.\n\nInspiré d'Obsidian et Maltego."),
        ("mod_autoscan", "⚡ Scan auto", "façon SpiderFoot", "Donne une cible (pseudo, email, domaine, IP, nom…) : l'outil lance toutes les recherches possibles, puis recommence sur ce qu'il trouve, et remplit le graphe tout seul."),
        ("mod_report", "📄 Rapport", "PDF · HTML", "Tout ce que tu as trouvé pendant la session, avec synthèse IA, en PDF (lisible sur iPhone) ou en page web."),
        ("mod_settings", "🔧 Réglages", "langue · IA locale · animations", "Langue, modèles d'IA locale (Ollama), animations, token Discord, dossier des résultats."),
        ("discord", "💬 Discord", discord[8:], "Rejoins la communauté Cat.exe : challenges, classement, nouvelles vidéos."),
        ("quit", "🚪 Quitter", "", "Fermer Cat.exe."),
    ]),
]


KEYW = {"mod_bodacc": "bodacc entreprise liquidation dirigeant societe annonce legale", "mod_iban": "iban rib banque virement", "mod_vin": "vin voiture vehicule plaque carte grise", "mod_mac": "mac fabricant appareil wifi box", "mod_wayurls": "wayback archive fichiers pdf urls cdx", "mod_revimg": "google lens tineye yandex reverse image inversee", "mod_webcams": "webcam camera windy live", "mod_holehe": "holehe email comptes inscrit", "mod_harvest": "theharvester sous-domaines emails hunter", "mod_urlscan": "urlscan capture phishing scan", "mod_autoscan": "spiderfoot auto scan automatique", "mod_prosrc": "censys hunter intelx dehashed epieos osint framework", "mod_anon": "tor anonyme ip vpn proxy navigateur changer ip", "mod_maplink": "google maps waze lien coordonnees gps", "mod_photobatch": "dossier exif trajet chronologie timeline", "mod_imgcompare": "hash similaire doublon retouche original", "mod_vidinfo": "youtube tiktok invid dataviewer date miniature", "mod_breaches": "hibp piratage fuite site", "mod_graph": "obsidian maltego toile liens enquete reseau", "mod_social": "sherlock maigret instagram tiktok reddit github profil", "mod_wmn": "whatsmyname sherlock pseudo username", "mod_iplookup": "ip geoip vpn tor shodan",
        "mod_img2gps": "gps coordonnees image photo exif geoclip", "mod_person": "nom prenom email linkedin", "mod_discord": "invite serveur snowflake",
        "mod_toolbox": "stegano strings cidr timestamp offline", "mod_pwned": "password mdp pwned hibp", "mod_ids": "snowflake timestamp tiktok date", "mod_video": "film mp4 frames", "mod_geo": "geoint gps localisation",
        "mod_headers": "mail phishing spf dkim", "mod_decode": "base64 cyberchef ctf", "mod_hash": "md5 sha256 virus malware", "mod_net": "ip asn mac whois",
        "mod_learn": "dev code programmer python cours apprendre javascript", "mod_archive": "wayback", "mod_satellite": "esri imagery historique", "mod_diagnostics": "diagnostic système dépendances python rich pillow heic ollama ffmpeg playwright"}
