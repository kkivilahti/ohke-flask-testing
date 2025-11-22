# Seminaarityö: Flask-backendin testausta

Tässä seminaarityössä tutustun Flask-backendin testaukseen osana Ohjelmistoprojekti 2 -kurssin projektiani ([Reddit Analyzer](https://github.com/ohjelmistoprojekti-ii-reddit-app)).

**Sisällysluettelo**:
- [Johdanto](#johdanto)
- [Testauksen perusteet](#testauksen-perusteet)
- [Testaussuunnitelma](#testaussuunnitelma)
- [Testitapaukset](#testitapaukset)
- [Testauksen työkalut](#testauksen-työkalut)
- [Testiympäristön pystytys](#testiympäristön-pystytys)
- [Testien toteutus](#testien-toteutus)
- [GitHub Actions -integraatio](#github-actions--integraatio)
- [Lähteet](#lähteet)
- [Tekoälyn käyttö](#tekoälyn-käyttö-työn-toteutuksessa)


## Johdanto

Valitsin seminaarityöni aiheeksi **testauksen**, koska se on arvostettu taito työelämässä ja ohjelmistokehityksen osa-alue, jossa haluan kehittyä. Aiempi kokemukseni koostuu pääasiassa yksittäisten testien kirjoittamisesta, enkä ole koskaan toteuttanut testausta osana laajempaa kehitysprosessia. Käynnissä oleva **Ohjelmistoprojekti 2** -kurssi tarjoaa tähän erinomaisen mahdollisuuden: olen mukana kehittämässä **Reddit Analyzer** -sovellusta, ja projekti on edennyt jo viimeiseen sprinttiin ilman, että sovellusta olisi vielä testattu lainkaan.

Lähes valmis projekti tarjoaa kiinnostavat ja osin haastavatkin lähtökohdat testaamiselle. Kehityksen loppuvaiheessa ja julkaisun lähestyessä on erityisen tärkeää varmistaa sovelluksen toimivuus ja laatu. Odotan mielenkiinnolla, kuinka testattavaa nykyinen koodi on ja millaisia kehityskohteita testaus tuo esiin.

Minulle tämä seminaarityö on paitsi uusien testausmenetelmien ja -työkalujen opettelua, myös laadullinen tutkimus projektistamme. 

### Projektin tausta

**Reddit Analyzer** on web-sovellus, joka kerää ja analysoi Redditissä käytyjä keskusteluja tunnistaen niistä keskeisiä trendejä ja teemoja sekä keskustelujen sävyjä. Analyysit, kuten aihemallinnus ja sentimenttianalyysi, on toteutettu valmiita malleja (esim. BERTopic, VADER) hyödyntäen, ja ne on automatisoitu **GitHub Actions**in avulla. Tulokset tallennetaan `MongoDB Atlas` -tietokantaan, josta ne tarjoillaan käyttäjälle `Flask`-backendin REST-rajapinnan kautta. `Next.js`-pohjainen frontend esittää analyysien tulokset visuaalisessa muodossa, esimerkiksi kaavioina ja karttanäkymänä.

```mermaid
---
title: Reddit Analyzer -sovelluksen arkkitehtuuri
---
flowchart LR
    %% GitHub Actions
    subgraph A["GitHub Actions"]
        A1["Ajastettu tai <br/> manuaalinen trigger"] --> A2["Reddit API -kyselyt"] --> A3["Analyysit, kuten <br/> aihemallinnus ja <br/> sentimenttianalyysi"]
    end

    subgraph B["Tietokanta"]
        B1["MongoDB Atlas"]
    end

    A3 -- tulosten tallennus --> B1

    %% Backend
    subgraph C["Flask-backend"]
        C1["REST API, käyttäjähallinta <br/> ja tietokantayhteydet"]
    end

    C1 --> B1
    B1 --> C1

    %% Frontend
    subgraph D["Next.js-frontend"]
        D1["Datan haku ja visualisointi"]
    end

    D1 --> C1
    C1 --> D1

    K["Käyttäjä"]
    K --> D1
    D1 --> K
```

Arkkitehtuurikaavio havainnollistaa, miten sovelluksen eri osat liittyvät toisiinsa ja mitä niiden vastuualueisiin kuuluu. Analyysiputket on eroteltu omaksi kokonaisuudekseen, koska ne ajetaan **GitHub Actions** -ympäristössä GitHubin virtuaalikoneilla, eivätkä siten kuulu Flask-backendin suoritusympäristöön. Backendin keskeiset osa-alueet ovat **REST-rajapinta, käyttäjähallinta sekä tietokantayhteydet**, kun taas frontend vastaa datan visualisoinnista ja käyttäjän vuorovaikutuksesta sovelluksen kanssa.

Reddit Analyzer on kehitetty viisihenkisessä tiimissä ketterien menetelmien mukaisesti. Oma roolini on painottunut backendin kehitykseen: olen vastannut muun muassa analyysiputkien suunnittelusta ja automatisoinnista sekä tilaustoiminnon toteutuksesta. 

<details>
<summary><strong>Reddit Analyzer -sanastoa</strong></summary>

- **Reddit** - laaja ja tunnettu verkkokeskustelualusta
- **Subreddit** - aihekohtainen keskustelualue Redditissä (esim. [r/Suomi](https://www.reddit.com/r/Suomi/), [r/technology](https://www.reddit.com/r/technology/))
- **Postaus** - käyttäjän julkaisema viesti subredditissä
- **Reddit API** - Redditin tarjoama rajapinta, jonka kautta sovellus hakee Redditistä postauksia ja niiden kommentteja
- **Aihemallinnus** (topic modeling) - NLP-tekniikka, jota käytetään tunnistamaan suurista tekstiaineistoista toistuvia teemoja
- **Sentimenttianalyysi** - NLP-tekniikka, jota käytetään tunnistamaan tekstien sävyä (positiivinen, negatiivinen, neutraali)
- **Analyysiputki** - GitHub Actionsissa ajettava automatisoitu prosessi, joka sisältää postausten haun Reddit APIsta, analyysit, joiden sisältö vaihtelee analyysin tyypistä riippuen (esim. trendianalyysi, tilauskohtainen analyysi), sekä tallennuksen tietokantaan

</details>

### Seminaarityön tavoitteet

Tässä seminaarityössä keskityn **backend-testaukseen**, koska se tarjoaa monipuolisia oppimiskokemuksia ja mahdollisuuden syventyä teknisesti haastaviin osa-alueisiin. **Reddit Analyzerin** backendissa hallinnoidaan muun muassa token-perusteista autentikaatiota ja tietokantayhteyksiä, joiden testaamisesta minulla ei ole aiempaa kokemusta. Myös Python-pohjaisen sovelluksen testaaminen on minulle uutta, mikä tekee aiheesta erityisen opettavaisen.

Tavoitteeni on suunnitella ja toteuttaa testausprosessi selkeästi ja systemaattisesti. **Allure Report** otetaan käyttöön heti alkuvaiheessa, jotta testausprosessin eteneminen ja tulosten analysointi olisi läpinäkyvää ja helposti seurattavaa.

Testauksen automatisointi **GitHub Actions** -ympäristössä on valinnainen lisä: se olisi oppimisen kannalta arvokasta, mutta en pidä sitä välttämättömänä, koska projekti on jo loppusuoralla. Automatisoiduista testeistä olisi ollut eniten hyötyä projektin aikaisemmissa vaiheissa, jolloin ne olisivat toimineet kehityksen jatkuvana tukena. Tässä vaiheessa testauksen ensisijainen tavoite on varmistaa sovelluksen toimivuus ja vakaus ennen julkaisua.

Seminaarityössä keskityn seuraaviin osa-alueisiin:
1. Testauksen suunnittelu
2. Testien toteuttaminen
3. Testitulosten visualisointi **Allure Report** -työkalulla
4. Testitulosten analysointi ja hyödyntäminen ohjelmiston laadun arvioinnissa
5. Testauksen automatisointi **GitHub Actions** -ympäristössä (jos aikaa jää)

Näin työ toimii paitsi käytännön oppimiskokemuksena myös osana projektin laadunvarmistusta.

### Suunnitellut teknologiat

- **Flask** - kevyt Python-pohjainen web-kehys, jota on käytetty Reddit Analyzerin backendin toteutukseen
- **Pytest** - Pythonin suosittu testauskehys, joka tukee yksikkö-, integraatio- ja järjestelmätason testejä
- **Mongomock** - kirjasto, joka simuloi MongoDB:n toimintaa ja mahdollistaa tietokantaoperaatioiden testaamisen ilman oikeaa tietokantayhteyttä
- **GitHub Actions** - GitHubin sisäänrakennettu CI/CD-ympäristö, jonka avulla testit ja muut työnkulut voidaan ajaa automaattisesti koodimuutosten yhteydessä tai esimerkiksi ajastettuna
- **Allure Report** - työkalu, joka visualisoi testitulokset vuorovaikutteisena HTML-sivuna ja tarjoaa kokonaiskuvan testien tuloksista, kattavuudesta ja kehityksestä ajan myötä

<p align="right"><a href="#seminaarityö-flask-backendin-testausta">⬆️</a></p>


## Testauksen perusteet

ℹ️ Hahmottaakseni testien suunnittelua paremmin, kertasin hieman testauksen teoriaa. Jos haluatte painottaa arvioinnissa enemmän teknistä toteutusta, tätä osiota ei ole pakko sisällyttää mukaan.

<details>
<summary><strong>Katso teoriaosio</strong></summary>

Ennen testauksen suunnittelua haluan kerrata lyhyesti keskeiset testauksen periaatteet ja käsitteet. Teoriapohjana hyödynnän Jussi Pekka Kasurisen kirjaa *Ohjelmistotestauksen käsikirja*, johon tutustuin Haaga-Helian Ohjelmistotestauksen kurssilla tänä syksynä.

### Testauksen merkitys

Testaus on keskeinen osa ohjelmistokehitystä, ja sen tarkoituksena on varmistaa, että ohjelmisto **toimii suunnitellusti** ja **täyttää** käyttäjien sekä sidosryhmien **vaatimukset**. Testauksen avulla voidaan havaita vikoja ja puutteita, jotka muuten saattaisivat johtaa ohjelmiston epätoivottuun toimintaan. (Kasurinen, luku 1)

### Testauksen tasot ja menetelmät

Kasurisen kirjan mukaan testauksessa on useita tasoja ja menetelmiä, jotka kattavat ohjelmiston eri osa-alueita ja tarjoavat laadunvarmistukseen eri näkökulmia. Testauksen tasoja kuvataan kirjan sivuilla 50-57 ja menetelmiä sivuilla 64-68.

**Yksikkötestaus** kohdistuu yksittäisen moduulin, funktion tai olion toiminnan varmentamiseen. Testeillä voidaan tarkistaa esimerkiksi erilaisten syötteiden käsittely, raja-arvot ja poikkeustilanteiden hallinta.

**Integraatiotestaus** tarkastelee ohjelmiston eri osien yhteistoimintaa. Sen avulla varmistetaan, että eri moduulit ja rajapinnat kommunikoivat oikein keskenään.

**Järjestelmätestaus** kohdistuu koko järjestelmään, ja sen tarkoituksena on varmistaa, että ohjelmisto toimii kokonaisuutena ja täyttää sille asetetut vaatimukset.

**Mustalaatikkotestaus** on menetelmä, jossa ohjelmistoa arvioidaan sen ulkoisen käyttäytymisen, eli syötteiden ja niistä tuotettujen tulosten perusteella. Testaajalla ei ole tietoa ohjelmiston sisäisestä toteutuksesta.

**Lasilaatikkotestaus** on menetelmä, jossa testaus perustuu ohjelmiston sisäisen rakenteen ja logiikan tuntemiseen. Testaaja suunnittelee testit syötteiden lisäksi myös sen perusteella, miten ohjelmisto on toteutettu ja mitä sen sisällä tapahtuu.

### Testauksen suunnittelu

Kasurisen kirjassa (s. 117-118) kuvataan esimerkkinä **SPACE DIRT** -menetelmän mukaisen **testaussuunnitelman** vaiheet:
- **S**cope - laajuus: mitä kohteita testataan ja mitä osia ei testata
- **P**eople - ihmiset: millaista koulutusta testaajilta vaaditaan, mitkä ovat testaajien vastuut
- **A**pproach - lähestymistapa: mitä testausmenetelmiä käytetään
- **C**riteria - kriteerit: mitkä ovat testauksen aloitus-, lopetus-, keskeytys- ja jatkamiskriteerit
- **E**nvironment - ympäristö: millainen testiympäristö testausta varten tulee rakentaa
- **D**eliverables - tuotokset: mitä testausprosessi tuottaa kehitysprosessin käyttöön
- **I**ncidentals - satunnaiset: mitä erikoisominaisuuksia tai poikkeuksia testaukseen liittyy
- **R**isks - riskit: riskit ja niiden torjunta
- **T**asks - tehtävät: tehtävät, jotka kuuluvat testausprosessiin

Testaussuunnitelman sisältö voi vaihdella projektin ja tilanteen mukaan, joten SPACE DIRT on vain yksi esimerkki. SPACE DIRT ja muut standardien mukaiset testaussuunnitelman sopivat kenties parhaiten suuriin projekteihin - pienemmässä projektissa niitä voi soveltaa poimimalla mukaan oman projektin kannalta keskeiset osa-alueet. Yleensä testaussuunnitelmassa kirjataan ainakin mitä ohjelmasta testataan, missä vaiheessa ja millä menetelmällä (Kasurinen, s.116).

### Testitapausten suunnittelu

Testaussuunnitelman jälkeen suunnitellaan **testitapaukset**, jotka kuvaavat yksittäisiä työvaiheita tai tapahtumaketjuja, joiden seurauksena järjestelmä suorittaa jonkin tehtävän. Kuvauksessa voidaan mainita esimerkiksi testin vaiheet ja odotettu lopputulos ja mitä testillä halutaan varmistaa.

Hyvien käytäntöjen mukaan testitapauksia tulisi määritellä koko projektin elinkaaren ajan, aina kun tulee uusia ominaisuuksia tai kun havaitaan jokin vika tai ongelma. Testitapaukset kannattaa kohdistaa tunnetusti virhealttiisiin ohjelmiston osiin, kuten uuteen koodiin, ominaisuuteen tai teknologiaan. Testitapauksia voi syntyä paljon, jolloin niitä joudutaan priorisoimaan esimerkiksi **riskikartoituksen** avulla. (Kasurinen, s. 118-121)

Kasurisen (s. 122-123) mukaan testitapausten valintaan on kaksi päämenetelmää:
- **Suunnitelmalähtöinen testitapausten valinta**: pyritään kattamaan kaikki ohjelmistolle asetetut laatuvaatimukset mahdollisimman kustannustehokkaasti
- **Riskilähtöinen testitapausten valinta**: keskitytään poistamaan isoimmat ongelmat ja varmistamaan pääominaisuuksien toiminta

### Projektikohtainen pohdinta

Omassa projektissani vaatimusten täyttymisen todentaminen on osittain haasteellista, koska kunnollista vaatimusmäärittelyä ei ole laadittu. Meillä on vain lista käyttäjätarinoita, jotka olemme purkaneet konkreettisiksi tehtäviksi projektitaulussa. Tämän vuoksi testauksen painopiste on erityisesti sovelluksen keskeisten toimintojen **toimivuuden varmistamisessa ja vikojen löytämisessä**. Samalla testaus toimii välineenä arvioida projektin laatua käytännössä.

Pääpaino tulee olemaan **yksikkö- ja integraatiotesteissä**, koska ne soveltuvat backendin REST-rajapinnan ja tietokantayhteyksien testaamiseen parhaiten. Järjestelmätestaus, ainakin Kasurisen kirjan määritelmän mukaisesti, olisi vaikea toteuttaa puutteellisten vaatimusmäärittelyjen sekä rajallisten resurssien vuoksi.

Projektin kokoon ja aikatauluun nähden täysimittainen SPACE DIRT -testaussuunnitelma olisi ylimitoitettu. Käytän sitä kuitenkin inspiraationa oman, kevyemmän testaussuunnitelman laatimisessa, joka keskittyy sovelluksen tärkeimpiin osiin ja riskilähtöiseen priorisointiin. Näin pystyn yhdistämään teorian ja käytännön tarpeet, ja testausprosessi pysyy selkeänä ja johdonmukaisena.

</details>

<p align="right"><a href="#seminaarityö-flask-backendin-testausta">⬆️</a></p>


## Testaussuunnitelma

ℹ️ Jotta testausprosessi olisi mahdollisimman hallittu ja tehokas, laadin melko kattavan testaussuunnitelman. Jos haluatte painottaa arvioinnissa enemmän teknistä toteutusta, tätä osiota ei ole pakko sisällyttää mukaan. Osion lukeminen auttaa kuitenkin hahmottamaan työn tulevia osioita, kuten testitapausten suunnittelua. *Testattavat osa-alueet* -osio auttaa lisäksi ymmärtämään Reddit Analyzerin toimintaa.

<details>
<summary><strong>Katso testaussuunnitelma</strong></summary>

Testaussuunnitelma pohjautuu Kasurisen kuvaamiin testauksen periaatteisiin ja SPACE DIRT -malliin, jota on kevennetty Reddit Analyzer -projektiin sopivaksi.

### Testauksen tavoite ja laajuus

Testauksen tavoitteena on varmistaa Reddit Analyzerin backendin **keskeisten toimintojen toimivuus ja vakaus** ennen julkaisua. Lisäksi testit tukevat projektin **laadun arviointia**, esimerkiksi sovelluksen luotettavuuden ja mahdollisten vikojen kartoittamista, sekä paljastavat ratkaisujen **vahvuuksia ja puutteita**.

Testauksen kohteena ovat:
- **Tietokantayhteydet (MongoDB)** - CRUD-operaatiot
- **REST API** - vasteet, virheidenkäsittely ja raja-arvot
- **Token-pohjainen käyttäjähallinta ja autentikointi** - rekisteröinti, kirjautuminen ja tokenien validointi

Testaus **ei kata** analyysiputkia, koska ne ajetaan erillisessä automatisoidussa ympäristössä (*GitHub Actions*) eivätkä siten kuulu backendin suoritusympäristöön. Tämän vuoksi myös ulkoiset palvelut, kuten Reddit API, sekä analyyseissa käytettävät kirjastot (esim. BERTopic) jäävät testien ulkopuolelle. GitHub Actions tarjoaa kuitenkin työnkuluista suoraa palautetta lokeissa, mikä helpottaa analyysien toimivuuden seurantaa.

Frontendin testaus ei kuulu tämän suunnitelman piiriin, sillä se on toisen tiimin jäsenen vastuulla.

### Testauksen lähestymistapa

Testauksessa noudatetaan **"testit ensin, refaktorointi jälkeen"** -periaatetta: testit kirjoitetaan ensin kaikille keskeisille toiminnoille, vaikka ne aluksi epäonnistuisivat, ja korjaukset toteutetaan lopuksi testien ohjaamana. Toiveena on, että tämä lähestymistapa auttaisi antamaan selkeän kuvan sovelluksen ongelmakohdista. Mikäli lähestymistapa osoittautuu liian haastavaksi tai aikaa vieväksi, voidaan siirtyä perinteisempään menetelmään, jossa refaktorointi ja testaus tehdään rinnakkain.

Koska vaatimusmäärittelymme on vajavaista eikä esimerkiksi hyväksymiskriteerejä ole määritelty, suunnittelen testit pääasiassa sen perusteella, mitä ajattelen sovelluksen toimintojen **kuuluvan** tehdä. Tämä tukee testauksen päätavoitetta, eli sovelluksen kriittisten osien toimivuuden ja vakauden varmistamista. Testitapausten ja testien suunnittelussa hyödynnetään **lasilaatikkomenetelmää**, eli testejä suunnitellaan tarkastelemalla suoraan testattavien funktioiden rakennetta ja logiikkaa.

Testauksessa hyödynnetään **pytest**iä yksikkö- ja integraatiotestien toteutukseen sekä **Allure Report**ia testitulosten visualisointiin. **Mongomock**ia käytetään tietokantatoimintojen simuloimiseen, jotta testit voidaan suorittaa ilman vaikutusta tuotantotietokantaan. Yksikkötesteillä varmistetaan yksittäisten funktioiden ja metodien toiminta, ja integraatiotesteillä testataan eri komponenttien, kuten REST API:n ja tietokannan, yhteistoimintaa.

### Testattavat osa-alueet

#### REST API ja käyttäjähallinta

REST APIn kautta hallinnoidaan kaikkia Reddit Analyzerin keskeisiä toimintoja, jotka ovat trendianalyysi, maakohtainen subreddit-analyysi, tilauspohjainen subreddit-analyysi sekä käyttäjähallinta. **Analyysit suoritetaan automatisoidusti Actionsin kautta**, ja niiden kohdalla rajapintaa käytetään lähinnä analyysitulosten välittämiseen. Tässä lyhyt kuvaus keskeisistä toiminnoista ja niiden yhteydestä rajapintaan:
- **Trendianalyysi**: suuresta määrästä Reddit-postauksia tunnistetaan trendaavia aiheita aihemallinnuksen avulla; sitten tehdään aihekohtaiset tiivistelmät kielimallin avulla, sekä aihekohtainen sentimenttianalyysi. Rajapinnan kautta tarjoillaan subredditit, joille analyyseja säännöllisesti suoritetaan, sekä näiden analyysien tuloksia ja tilastotietoja.
- **Maakohtainen subreddit-analyysi**: pieni määrä maakohtaisia Reddit-postauksia käsitellään kielenkäännöksellä (tarvittaessa) ja sentimenttianalyysilla. Rajapinnan kautta tarjoillaan maakohtaiset subredditit, joille analyyseja säännöllisesti suoritetaan, sekä näiden analyysien tuloksia.
- **Käyttäjähallinta**: Käyttäjähallinnassa hallinnoidaan rekisteröitymistä, kirjautumista ja uloskirjautumista rajapinnan kautta. Käyttäjän autentikointiin käytetään access- ja refresh-tokeneita: access-tokenilla pääsee tekemään rajapintapyynnöt, ja refresh-tokenilla voi tarvittaessa uusia access-tokenin. Logout poistaa käytössä olevan access-tokenin ja merkitsee refresh-tokenin mitätöidyksi.
- **Tilauspohjainen subreddit-analyysi**: käyttäjä voi tilata analyysit haluamaansa subredditiin, haluamallaan analyysityypillä (*posts* tai *topics*), ja tilausten pohjalta suoritetaan analyysit säännöllisesti Actionsin kautta. Rajapinnan kautta suoritetaan toimintoja kuten tilauksen lisäys, deaktivointi, ja tilauskohtaisten analyysitulosten haku.

| Toiminto | Endpoint | Metodi | Kuvaus |
| -------- | -------- | ------ | ------ |
| Trendianalyysi | `/api/subreddits` | GET | Hakee listan subredditeistä, joita analysoidaan automatisoidussa putkessa säännöllisesti | 
| Trendianalyysi | `/api/topics/latest/<subreddit>` | GET | Hakee tuoreimman analyysin tulokset valitulle subredditille | 
| Trendianalyysi | `/api/statistics/<subreddit>/<days>` | GET | Hakee tilastot analysoitujen postausten määristä valitulla aikavälillä |
| Trendianalyysi | `/api/statistics/topics/<subreddit>/<days>/<limit>` | GET | Hakee tilastot useimmiten esiintyvistä aiheista valitulla aikavälillä | 
| Maakohtainen analyysi | `/api/subreddits/countries` | GET | Hakee listan maakohtaisista subredditeistä, joita analysoidaan automatisoidussa putkessa säännöllisesti | 
| Maakohtainen analyysi | `/api/countries/latest/<subreddit>` | GET | Hakee tuoreimman analyysin tulokset valitulle maakohtaiselle subredditille |
| Käyttäjähallinta | `/api/authentication/register` | POST | Luo uuden käyttäjätunnuksen | 
| Käyttäjähallinta | `/api/authentication/login` | POST | Autentikoi käyttäjän ja palauttaa access- ja refresh-tokenit |
| Käyttäjähallinta | `/api/authentication/refresh` | POST | Vaihtaa refresh-tokenin uudeksi access-tokeniksi | 
| Käyttäjähallinta | `/api/authentication/logout` | DELETE | Peruu access-tokenin ja revokoi refresh-tokenin (kirjaa käyttäjän ulos) |
| Käyttäjähallinta | `/api/authentication/delete` | DELETE | Poistaa käyttäjätunnuksen sekä siihen liittyvät mahdolliset aktiiviset tilaukset |
| Tilaustoiminto | `/api/subscriptions/type/<type>` | GET | Hakee aktiiviset tilaukset analyysityypin mukaan | 
| Tilaustoiminto | `/api/subscriptions/current-user` | GET | Hakee aktiiviset tilaukset nykyiselle käyttäjälle | 
| Tilaustoiminto | `/api/subscriptions/current-user/add/<subreddit>/<type>` | POST | Luo tilauksen nykyiselle käyttäjälle valitulla subredditillä ja analyysityypillä |
| Tilaustoiminto | `/api/subscriptions/current-user/deactivate` | PATCH | Deaktivoi nykyisen käyttäjän tilauksen |
| Tilaustoiminto | `/api/subscriptions/current-user/latest-analyzed` | GET | Hakee tuoreimmat analyysitulokset nykyisen käyttäjän tilaukselle |

Olen ylemmästä listauksesta jättänyt pois kaksi endpointia, jotka hakevat ja analysoivat Reddit-dataa reaaliajassa, sillä en aio suorittaa niille testausta; ne toimivat lähinnä demotarkoituksessa, eikä niitä käytetä frontendin puolelta.

Tarkka kuvaus kaikista endpointeista, sisältäen mm. esimerkkipyynnöt ja -vastaukset, löytyy Reddit Analyzerin backendin [dokumentaatiosta](https://github.com/ohjelmistoprojekti-ii-reddit-app/reddit-app-backend?tab=readme-ov-file#-rest-api).

#### Tietokanta

Reddit Analyzerin tietokanta on toteutettu [MongoDB Atlas](https://www.mongodb.com/docs/atlas/) -palvelussa, joka mahdollistaa tietokannan hallinnoinnin kätevästi web-käyttöliittymän kautta. MongoDB on NoSQL-dokumenttitietokanta, jossa data tallennetaan JSON-muotoisiin dokumentteihin. Dokumenttien data organisoidaan *kokoelmiin* (eng. collection), jotka vastaavat relaatiotietokannan *tauluja*. Dokumenttitietokannassa data voi olla monimuotoista, koska skeemat eivät ole pakollisia. MongoDB:stä voi lukea lisää esimerkiksi [täältä](https://www.mongodb.com/docs/manual/introduction/).

Reddit Analyzerin tietokanta sisältää seuraavat kokoelmat:

| Kokoelma | Sisältö |
| -------- | ------- |
| `posts` | Sisältää trendi- ja sentimenttianalyysien tulokset valikoiduille subredditeille. (Data on järjestetty aihemallinnuksessa tunnistettujen aiheiden mukaan, joten selkeämpi kokoelman nimi voisi olla **topics**.) |
| `countries` | Sisältää maakohtaisten subredditien analyysitulokset. Maakohtaisten subredditien analyysiin sisältyy postausten kääntäminen englanniksi (tarvittaessa) sekä postauskohtainen sentimenttianalyysi. |
| `users` | Sisältää rekisteröityneiden käyttäjien tiedot. |
| `subscriptions` | Sisältää käyttäjien tekemät subreddit-tilaukset ja mm. valitun analyysityypin. | 
| `subscription_data` | Sisältää tilausten pohjalta tuotetut analyysitulokset. Tulosten muoto vaihtelee analyysityypin mukaan: `topics`-analyysi sisältää aihemallinnuksen ja aihekohtaisen sentimenttianalyysin, ja `posts`-analyysi sisältää postauskohtainen sentimenttianalyysin. |

Tietokantayhteyksiä hallitaan backendissa erillisen tietokantakerroksen kautta, joka tarjoaa yleiset funktiot esimerkiksi datan tallennukseen, hakuun ja päivitykseen. Tämä mahdollistaa keskitetyn tietokannan hallinnan ja toivon mukaan helpottaa testien toteutusta. 

On hyvä huomioida, että testaus **ei perustu** tuotantotietokannan dataan, vaan testauksessa käytetään erillistä testitietokantaa (*Mongomock*). Yllä olevan tietokantakuvauksen tarkoitus on auttaa hahmottamaan sovelluksen datavirtoja ja toimintaa.

### Testien priorisointi

Testitapauksia ja testejä priorisoidaan **riskilähtöisesti** niin, että sovelluksen ydintoiminnot varmistetaan ensin, ja vähemmän kriittiset osat testataan myöhemmin. Osa-alueiden prioriteettijärjestys on seuraava:
1. **Tietokantayhteydet**
2. **REST API**
3. **Käyttäjähallinta ja autentikointi**

Tietokanta on sovelluksen kriittisin osa, koska kaikki analysoitu data ja käyttäjätiedot kulkevat sen kautta. Ilman toimivaa tietokantaa sovelluksen ydintoiminnot eivät ole käytettävissä, ja frontend jäisi käytännössä tyhjäksi. REST API on toiseksi tärkein osa, sillä frontendin toiminta ja datan käsittely riippuvat siitä. Käyttäjähallinta tuo sovellukseen lisäominaisuuksia, mutta ei ole käytön kannalta välttämätöntä, joten se on prioriteettilistalla alempana. 

Myös yksittäisille **testitapauksille** annetaan prioriteettiluokitus, kuten **korkea, keskitaso tai matala**, sen mukaan, kuinka tärkeä testi on sovelluksen ydintoimintojen varmistamisen kannalta.

Täten testejä priorisoidaan kahdella tasolla:
1. **Osa-alueen kriittisyys** - määrittää, missä järjestyksessä sovelluksen osia testataan (tietokanta → REST API → käyttäjähallinta)
2. **Testitapausten kriittisyys** - määrittää, missä järjestyksessä testejä suoritetaan saman osa-alueen sisällä (edeten korkeimmasta prioriteetista matalimpaan)

### Testiympäristö

Testit suoritetaan ensisijaisesti **paikallisessa** Pythonin virtuaaliympäristössä. Jos aikataulu sallii, voidaan testien suoritus siirtää automatisoituun GitHub Actions -ympäristöön.

### Testauksen kriteerit

Seuraavat kriteerit ohjaavat testausprosessia ja pitävät sen hallittavana:
- **Aloituskriteerit**: Tarvittavat kirjastot ja riippuvuudet on asennettu, backendin perustoiminnot toimivat paikallisesti, ja testiympäristö on pystytetty.
- **Lopetuskriteerit**: Kaikki yksikkö- ja integraatiotestit on suoritettu ja kriittiset testit on läpäisty. Mahdolliset epäonnistuneet testit on dokumentoitu ja ratkaistu.
- **Keskeytyskriteerit**: Testaus voidaan päättää, jos ilmenee odottamattomia ongelmia, kuten virheitä testiympäristössä, tai jos aika loppuu kesken.

### Testauksen tuotokset

Testauksen tulokset kootaan **Allure Report** -raporttiin, joka tarjoaa visuaalisen yhteenvedon testien kulusta, onnistumisista ja havaitusta virheistä. Raporttia voidaan käyttää apuna testitulosten analysoinnissa ja dokumentoinnissa.

</details>

<p align="right"><a href="#seminaarityö-flask-backendin-testausta">⬆️</a></p>



## Testitapaukset

Seuraavaksi kuvaan keskeiset testitapaukset, jotka pohjautuvat edellä esitettyyn testaussuunnitelmaan. Testitapaukset on ryhmitelty testattavien osa-alueiden mukaan (tietokanta, REST API, käyttäjähallinta). Tavoitteena on suunnitella testitapaukset niin, että ne on helppo jäljittää koodista ja Allure Report -raportista suunnitelmaan. 

Koska vaatimusmäärittelymme on vajavaista eikä esimerkiksi hyväksymiskriteerejä ole määritelty, suunnittelen testitapauksia pääasiassa sen perusteella, mitä ajattelen sovelluksen toimintojen **kuuluvan** tehdä.

### Tietokantatestit

Tietokantatestit tulevat olemaan yksikkötestejä. Tietokantamme data on moninaista, emmekä ole määritelleet skeemoja tai pakollisia arvoja, joten en aio keskittyä validoimaan datan eheyttä. Sen sijaan teen muutamia esimerkkidokumentteja ja -kokoelmia, joita simuloin testitietokannassa, varmistaakseni tietokantafunktioiden toiminnan.

#### TC-01 - Data tallennetaan tietokantaan
**Kuvaus**: Testaa `save_data_to_database(data_to_save, collection)` -funktion toimintaa, varmistaen että data **tallentuu oikein** ja virhetilanteet käsitellään asianmukaisesti.<br>
**Prioriteetti**: korkea

| # | Testivaihe | Tavoite | Syöte tai parametri | Odotettu tulos |
|---|------------|---------|---------------------|----------------|
| 1 | Tallennetaan yksittäinen dokumentti | Varmistaa, että yksittäisen dokumentin tallennus onnistuu | Validi dokumentti | Dokumentti lisätään kokoelmaan |
| 2 | Tallennetaan lista dokumentteja | Varmistaa, että useamman dokumentin tallennus onnistuu | Lista valideja dokumentteja | Kaikki dokumentit lisätään kokoelmaan |
| 3 | Tallennetaan tyhjä dokumenttilista | Varmistaa, että virheenkäsittely toimii | Tyhjä lista | `ValueError` tai vastaava |
| 4 | Tallennetaan väärän tyyppistä dataa | Varmistaa, että virheenkäsittely toimii | Virheellinen datatyyppi, kuten merkkijono | `TypeError` tai vastaava |


#### TC-02 - Data haetaan tietokannasta
**Kuvaus**: Testaa `fetch_data_from_collection(collection, filter=None)` -funktion toimintaa, varmistaen että datan **haku toimii oikein** ja virhetilanteet käsitellään asianmukaisesti.<br>
**Prioriteetti**: korkea

| # | Testivaihe | Tavoite | Syöte tai parametri | Odotettu tulos |
|---|------------|---------|---------------------|----------------|
| 1 | Hae kaikki dokumentit | Varmistaa, että kaikkien dokumenttien haku toimii normaalisti | Ei `filter`-parametria | Kaikki dokumentit palautetaan listana |
| 2 | Hae dokumentit käyttäen filtteriä | Varmistaa, että haku palauttaa suodatetut dokumentit oikein | Validi `filter` | Palauttaa suodatinta vastaavat dokumentit listana | 
| 3 | Hae dokumenttia, jota ei ole olemassa | Varmistaa, että haku palauttaa tyhjän listan, jos dokumenttia ei löydy | Invalidi `filter` (ei vastaa mitään dokumenttia) | Tyhjä lista |
| 4 | Hae dokumenttia virheellisellä filtterillä | Varmistaa, että virheenkäsittely toimii | Invalidi `filter`, esim. merkkijono | `TypeError` |


#### TC-03 - Dokumentin päivittäminen tietokannassa
**Kuvaus**: Testaa `update_one_item_in_collection(collection, filter, update)` -funktion toimintaa, varmistaen että datan **päivitys toimii oikein** ja virhetilanteet käsitellään asianmukaisesti.<br>
**Prioriteetti**: korkea

| # | Testivaihe | Tavoite | Syöte tai parametri | Odotettu tulos |
|---|------------|---------|---------------------|----------------|
| 1 | Päivitä olemassa oleva dokumentti | Varmistaa, että päivitys onnistuu | Validi `filter` ja `update` | Dokumentti päivitetään onnistuneesti | 
| 2 | Päivitä dokumenttia, jota ei ole olemassa | Varmistaa, että virheenkäsittely toimii | Invalidi `filter` (ei vastaa mitään dokumenttia) | `ValueError` tai vastaava |
| 3 | Päivitä dokumenttia virheellisellä filtterillä | Varmistaa, että virheenkäsittely toimii | Invalidi `filter`, esim. merkkijono | `TypeError` tai vastaava |


#### TC-04 - Dokumentin poistaminen tietokannasta
**Kuvaus**: Testaa `delete_one_item_from_collection(collection, filter)`, varmistaen että datan **poisto toimii oikein** ja virhetilanteet käsitellään asianmukaisesti.<br>
**Prioriteetti**: korkea

| # | Testivaihe | Tavoite | Syöte tai parametri | Odotettu tulos |
|---|------------|---------|---------------------|----------------|
| 1 | Poista olemassa oleva dokumentti | Varmistaa, että poisto onnistuu | Validi `filter` (vastaa olemassaolevaa dokumenttia) | Dokumentti poistetaan onnistuneesti |
| 2 | Poista dokumentti, jota ei ole olemassa | Varmistaa, että virheenkäsittely toimii | Invalidi `filter` (ei vastaa mitään dokumenttia) | `ValueError` tai vastaava |
| 3 | Poista dokumentti virheellisellä filtterillä | Varmistaa, että virheenkäsittely toimii | Invalidi `filter`, esim. merkkijono | `TypeError` tai vastaava |


> [!NOTE]
> Seuraavia analyysituloksia käsitteleviä testejä varten täytyy luoda hieman yksityiskohtaisempi datasetti, joka sisältää erityyppisiä analyysituloksia ja timestampit.
>
> Selkeyden vuoksi analyysituloksia käsittelevät testit kannattaa erotella perustoimintoja (kuten tallennus, päivitys) testaavista testeistä omiin tiedostoihinsa.


#### TC-05 - Uusimpien analyysitulosten haku valitulle subredditille
**Kuvaus**: Testaa `get_latest_data_by_subreddit(collection, subreddit, type=None)` -funktion toimintaa, varmistaen että funktio **palauttaa uusimman datan oikein** ja käsittelee virhetilanteet asianmukaisesti.<br>
**Prioriteetti**: korkea<br>

| # | Testivaihe | Tavoite | Syöte tai parametri | Odotettu tulos |
|---|------------|---------|---------------------|----------------|
| 1 | Hae uusimmat dokumentit ilman `type`-filtteriä | Varmistaa, että uusimmat dokumentit palautetaan oikein | Validi `subreddit` (vastaa testidataa) | Palauttaa dokumentin uusimmalla timestampilla |
| 2 | Hae uusimmat dokumentit `type`-filtterin kanssa | Varmistaa, että analyysityypin filtteriöinti toimii | Validi `subreddit` ja `type` (vastaa testidataa) | Palauttaa dokumentin uusimmalla timestampilla ja oikealla analyysityypillä |
| 3 | Hae dokumentteja subredditistä, jota ei ole olemassa | Varmistaa, että olemattomasta subredditistä haku käsitellään oikein | Invalidi `subreddit` | Tyhjä lista | 
| 4 | Hae virheellisellä `type`-parametrilla | Varmistaa, että virheenkäsittely toimii | Invalidi `type`, eli joku muu kuin *posts* tai *topics* | `ValueError` tai vastaava |


#### TC-06 - Postausmäärien laskeminen valitulla aikavälillä
**Kuvaus**: Testaa `get_post_numbers_by_timeperiod(subreddit, number_of_days)` -funktion toimintaa, varmistaen että funktio **laskee postausmäärät oikein** ja virhetilanteet käsitellään asianmukaisesti.<br>
**Prioriteetti**: keskitaso<br>
**Huomio**: Testidataan täytyy lisätä useamman päivän postauksia, jotta aggregointi toimii oikein.

| # | Testivaihe | Tavoite | Syöte tai parametri | Odotettu tulos |
|---|------------|---------|---------------------|----------------|
| 1 | Hae postaukset olemassaolevalle subredditille | Varmistaa, että postausmäärät lasketaan oikein | Validi `subreddit` ja `number_of_days` | Palauttaa listan postausmääristä, ja määrät ovat oikein |
| 2 | Hae postaukset subredditille, jota ei ole olemassa | Varmistaa, että olemattomasta subredditistä haku käsitellään oikein | Invalidi `subreddit` | Tyhjä lista |
| 3 | Hae virheellisellä `number_of_days`-parametrilla | Varmistaa, että virheenkäsittely toimii | Invalidi `number_of_days`, esim. negatiivinen luku | `ValueError` tai vastaava | 


#### TC-07 - Suosituimpien topicien haku valitulla aikavälillä
**Kuvaus**: Testaa `get_top_topics_by_timeperiod(subreddit, number_of_days, limit)` -funktion toimintaa, varmistaen että funktio **palauttaa topicit oikeassa järjestyksessä ja oikeilla määrillä** ja virhetilanteet käsitellään asianmukaisesti.<br>
**Prioriteetti**: keskitaso<br>
**Huomio**: Testidataan täytyy lisätä useamman päivän postauksia, jotta aggregointi toimii oikein.

| # | Testivaihe | Tavoite | Syöte tai parametri | Odotettu tulos |
|---|------------|---------|---------------------|----------------|
| 1 | Hae suosituimmat topicit olemassaolevalle subredditille | Varmistaa, että suosituimmat topicit lasketaan oikein | Validi `subreddit`, `number_of_days` ja `limit` | Palauttaa listan topiceja oikeassa järjestyksessä, topicien määrä == limit |
| 2 | Hae suosituimmat topicit subredditille, jota ei ole olemassa | Varmistaa, että olemattomasta subredditistä haku käsitellään oikein | Invalidi `subreddit` | Tyhjä lista |
| 3 | Hae suurella `limit`-arvolla | Varmistaa, että funktio palauttaa kaikki saatavilla olevat topicit eikä virhettä synny | Validi `subreddit`, suuri `limit` | Palauttaa kaikki suosituimmat topicit, ja määrä < `limit` | 
| 4 | Hae virheellisellä `number_of_days`-parametrilla | Varmistaa, että virheenkäsittely toimii | Invalidi `number_of_days`, esim. negatiivinen luku | `ValueError` tai vastaava |
| 5 | Hae virheellisellä `limit`-parametrilla | Ensure error handling works | Invalidi `limit`, esim. negatiivinen luku | `ValueError` tai vastaava |

<p align="right"><a href="#seminaarityö-flask-backendin-testausta">⬆️</a></p>


### REST API- ja käyttäjähallintatestit

REST API -testit toteutetaan testausuunnitelman mukaisessa prioriteettijärjestyksessä. Aluksi varmistetaan sovelluksen perustoiminnot, jotka ovat kaikkien käyttäjien saatavilla ilman kirjautumista. Tämän jälkeen testataan käyttäjähallinta (kuten kirjautuminen ja rekisteröinti), ja lopuksi kirjautumista vaativat toiminnot, varmistaen samalla, että virhetilanteet käsitellään oikein.

*Kaikki endpointit ja niiden tarkemmat kuvaukset on listattu [testaussuunnitelman](#testaussuunnitelma) osiossa "Testattavat osa-alueet".*

### Julkiset toiminnot (ei vaadi kirjautumista)

#### TC-08 - Hae lista subredditeistä
**Kuvaus**: Testaa `/api/subreddits`- ja `/api/subreddits/countries`-endpointien toimintaa varmistaen, että ne **palauttavat subredditit** oikein. Virhetilanteiden käsittely ei ole pakollista, koska subreddit-vaihtoehdot ovat staattisia.<br>
**Prioriteetti**: korkea

| # | Testivaihe | Tavoite | Syöte tai parametri | Odotettu tulos |
|---|------------|---------|---------------------|----------------|
| 1 | Hae lista subredditeistä, joita käytetään trendianalyysiin | Varmistaa, että subredditit palautetaan oikein | - | Status `200 OK` ja oikeat subredditit listana | 
| 2 |  Hae lista subredditeistä, joita käytetään maakohtaiseen analyysiin | Varmistaa, että subredditit palautetaan oikein | - | Status `200 OK` ja oikeat subredditit listana | 
| 3 | Tarkista kirjautumisen tarve maakohtaisilta subredditeiltä | Varmistaa, että osa subredditeistä on merkitty kirjautumista vaativiksi | - | Jokaisessa listan kohdassa on kenttä `login_required`, joka on 0 tai 1 |


#### TC-09 - Hae trendianalyysin tulokset
**Kuvaus**: Testaa `/api/topics/latest/<subreddit>`-endpointin toimintaa varmistaen, että se **palauttaa uusimmat analyysitulokset** valitulle subredditille ja käsittelee virhetilanteet asianmukaisesti.<br>
**Prioriteetti**: korkea

| # | Testivaihe | Tavoite | Syöte tai parametri | Odotettu tulos |
|---|------------|---------|---------------------|----------------|
| 1 | Hae analyysitulokset olemassaolevalle subredditille | Varmistaa, että endpoint palauttaa uusimmat tulokset oikein | Validi `subreddit` | Palauttaa listana tulokset, joissa on tuorein `timestamp` |
| 2 | Hae analyysitulokset subredditille, jota ei ole olemassa | Varmistaa, että virheenkäsittely toimii | Invalidi `subreddit` | Status `404 Not Found` tai vastaava |
| 3 | Tarkista datan sisältö | Varmistaa, että data vastaa tietokannan sisältöä | Validi `subreddit` | JSONin sisältö vastaa odotettua |


#### TC-10 - Hae maakohtaisen analyysin tulokset
**Kuvaus**: Testaa `/api/countries/latest/<subreddit>`-endpointin toimintaa varmistaen, että se **palauttaa uusimmat analyysitulokset** valitulle maakohtaiselle subredditille ja käsittelee virhetilanteet asianmukaisesti.<br>
**Prioriteetti**: korkea

| # | Testivaihe | Tavoite | Syöte tai parametri | Odotettu tulos |
|---|------------|---------|---------------------|----------------|
| 1 | Hae analyysitulokset olemassaolevalle subredditille | Varmistaa, että endpoint palauttaa uusimmat tulokset oikein | Validi `subreddit` | Palauttaa listana tulokset, joissa on tuorein `timestamp` |
| 2 | Hae analyysitulokset subredditille, jota ei ole olemassa | Varmistaa, että virheenkäsittely toimii | Invalidi `subreddit` | Status `404 Not Found` tai vastaava |
| 3 | Tarkista datan sisältö | Varmistaa, että data vastaa tietokannan sisältöä | Validi `subreddit` | JSONin sisältö vastaa odotettua |


#### TC-11 - Hae trendianalyysin postausmäärien tilastot
**Kuvaus**: Testaa `/api/statistics/<subreddit>/<days>`-endpointin toimintaa varmistaen, että se **palauttaa postausmäärien tilastot** valitulle subredditille ja käsittelee virhetilanteet asianmukaisesti.<br>
**Prioriteetti**: keskitaso

| # | Testivaihe | Tavoite | Syöte tai parametri | Odotettu tulos |
|---|------------|---------|---------------------|----------------|
| 1 | Hae tilastot olemassaolevalle subredditille | Varmistaa, että endpoint palauttaa tilastot oikein | Validi `subreddit` | Palauttaa tilastot listana |
| 2 | Hae tilastot subredditille, jota ei ole olemassa | Varmistaa, että virheenkäsittely toimii | Invalidi `subreddit` | Status `404 Not Found` tai vastaava |
| 3 | Tarkista datan sisältö | Varmistaa, että sisältö on oikeassa muodossa | Validi `subreddit` | JSONin sisältö vastaa odotettua |


#### TC-12 - Hae trendianalyysin tilastot suosituimmille topiceille
**Kuvaus**: Testaa `/api/statistics/topics/<subreddit>/<days>/<limit>`-endpointin toimintaa varmistaen, että se **palauttaa suosituimpien topicien tilastot** valitulle subredditille ja käsittelee virhetilanteet asianmukaisesti.<br>
**Prioriteetti**: keskitaso

| # | Testivaihe | Tavoite | Syöte tai parametri | Odotettu tulos |
|---|------------|---------|---------------------|----------------|
| 1 | Hae tilastot olemassaolevalle subredditille | Varmistaa, että endpoint palauttaa tilastot oikein | Validi `subreddit` | Palauttaa tilastot listana |
| 2 | Hae tilastot subredditille, jota ei ole olemassa | Varmistaa, että virheenkäsittely toimii | Invalidi `subreddit` | Status `404 Not Found` tai vastaava |
| 3 | Tarkista datan sisältö | Varmistaa, että sisältö on oikeassa muodossa | Validi `subreddit` | JSONin sisältö vastaa odotettua |

<p align="right"><a href="#seminaarityö-flask-backendin-testausta">⬆️</a></p>

### Käyttäjähallinta

#### TC-13 - Rekisteröi uusi käyttäjä
**Kuvaus**: Testaa `/api/authentication/register`-endpointia varmistaakseen, että **käyttäjän rekisteröinti toimii oikein** ja virheet käsitellään asianmukaisesti.<br>
**Prioriteetti**: Korkea

| # | Testivaihe | Tavoite | Syöte tai parametri | Odotettu tulos |
|---|------------|---------|---------------------|----------------|
| 1 | Rekisteröidy kelvollisilla tiedoilla | Varmistaa, että rekisteröinti onnistuu | Kelvollinen käyttäjätunnus, sähköposti, salasana | Status `201 Created`, käyttäjä löytyy tietokannasta |
| 2 | Rekisteröidy olemassa olevalla käyttäjätunnuksella | Varmistaa, että päällekkäiset käyttäjätunnukset käsitellään | Olemassa oleva käyttäjätunnus, kelvollinen sähköposti, salasana | Status `400 Bad Request` |
| 3 | Rekisteröidy olemassa olevalla sähköpostilla | Varmistaa, että päällekkäiset sähköpostit käsitellään | Kelvollinen käyttäjätunnus ja salasana, olemassa oleva sähköposti | Status `400 Bad Request` |
| 4 | Rekisteröidy virheellisillä tiedoilla | Varmistaa, että validointi toimii | Virheellinen sähköpostimuoto, liian lyhyt salasana tms. | Status `400 Bad Request` |
| 5 | Rekisteröidy puuttuvilla käyttäjätiedoilla | Varmistaa, että validointi toimii | Joku vaadittu tieto puuttuu, esim. email | Status `400 Bad Request`|

#### TC-14 - Kirjaudu sisään käyttäjänä
**Kuvaus**: Testaa `/api/authentication/login` -endpointia varmistaakseen, että **käyttäjän kirjautuminen toimii oikein** ja virheet käsitellään asianmukaisesti.<br>
**Prioriteetti**: Korkea

| # | Testivaihe | Tavoite | Syöte tai parametri | Odotettu tulos |
|---|------------|---------|---------------------|----------------|
| 1 | Kirjaudu sisään kelvollisilla tunnuksilla | Varmistaa, että kirjautuminen onnistuu | Kelvollinen käyttäjätunnus/sähköposti ja salasana | Status `200 OK`, token palautetaan |
| 2 | Kirjaudu sisään virheellisellä salasanalla | Varmistaa, että virhe käsitellään | Kelvollinen käyttäjätunnus/sähköposti ja virheellinen salasana | Status `401 Unauthorized`, virheilmoitus |
| 3 | Kirjaudu sisään olemattomalla käyttäjällä | Varmistaa, että virhe käsitellään | Virheellinen käyttäjätunnus/sähköposti ja salasana | Status `401 Unauthorized`, virheilmoitus |

> [!NOTE]
> Tässä kohtaa huomasin, että suunniteltuja testejä on jo merkittävä määrä (+40kpl) ja projektia on jäljellä alle viikko. Jäljellä oleva aikataulu ei realistisesti mahdollista kaikkien testitapausten perusteellista suunnittelua ja toteutusta.
>
> Näen parhaaksi aloittaa tässä vaiheessa testien toteutuksen varmistaakseni, että kriittiset ja prioriteetiltaan tärkeimmät testit ehditään implementoida ennen projektin määräaikaa. Mikäli aikaa jää, palaan täydentämään puuttuvia testitapauksia.

Suunnitellut testitapaukset:
- **Käyttäjähallinta (autentikointi)** - käyttäjän poistaminen ja uloskirjautuminen, token refresh
- **Käyttäjän lisäominaisuudet (vaatii kirjautumisen)** - tilaustoiminto

<p align="right"><a href="#seminaarityö-flask-backendin-testausta">⬆️</a></p>

## Testauksen työkalut

Tämä osio sisältää teoriaa ja koodiesimerkkejä työkaluista, joita testien toteuksessa käytetään.

<details>
    <summary><strong>Pytest</strong></summary>

Pytest on Pythonin suosittu testauskehys, jossa testit kirjoitetaan tavallisina funktioina ja testien onnistuminen tarkistetaan `assert`-väitteillä. Pytestin keskeisiä etuja ovat yksinkertainen syntaksi ja vähäinen määrä pakollista "boilerplate" koodia. Pytestin [dokumentaatiossa](https://docs.pytest.org/en/stable/how-to/assert.html) on seuraavia esimerkkejä testien kirjoittamisesta:
```python
def f():
    return 3

def test_function():
    assert f() == 4
```
Tämä testi epäonnistuu, koska `f` palauttaa arvon 3, mutta testissä odotetaan arvoa 4. Jos odotusarvo muutetaan vastaamaan toteutusta, testi menee läpi:
```python
    assert f() == 3
```

Poikkeusten testaaminen onnistuu tähän tyyliin `pytest.raises` -kontekstilla:
```python
def test_zero_division():
    with pytest.raises(ZeroDivisionError):
        1 / 0
```

Pytest löytää testit automaattisesti kaikista tiedostoista, joiden nimi on muodossa `test_*.py` tai `*_test.py`. Testejä voidaan ajaa seuraavilla komennoilla:
- Aja kaikki testit:
```
pytest
```
- Aja testit tietystä tiedostosta:
```
pytest tests/test_module.py
```

Testien valmistelua ja jaettujen resurssien hallintaa varten pytestissa voidaan käyttää **fixture**ja, jotka määritellään `conftest.py`-tiedostossa. Fixturen avulla voidaan luoda esimerkiksi testitietokanta, jota voidaan sitten käyttää testifunktioissa parametrina ilman erillistä importia.

Lähteet:
- [Testien kirjoittaminen ja assertin käyttö](https://docs.pytest.org/en/stable/how-to/assert.html)
- [Testien ajaminen](https://docs.pytest.org/en/stable/getting-started.html#run-multiple-tests)
- Fixturet: [1](https://docs.pytest.org/en/7.4.x/explanation/fixtures.html) & [2](https://flask.palletsprojects.com/en/stable/tutorial/tests/#setup-and-fixtures)
</details>

<details>
    <summary><strong>Allure Report</strong></summary>

Allure Report on työkalu, jonka avulla voidaan esittää testitulokset visuaalisesti interaktiivisen HTML-sivun muodossa. Allure on yhteensopiva monien eri testikehysten, kuten **pytest**in, **Playwright**in ja **Jest**in, kanssa. Raportti näyttää testien statukset, virheet, poikkeukset ja suoritusajat. Testejä voidaan organisoida eri tasoihin tai kategorioihin, ja niille voidaan määritellä esimerkiksi otsikoita, kuvauksia ja kriittisyysaste (*severity*).

> **Ohjeet Alluren käyttöönottoon löytyvät raportin osiosta [Testiympäristön pystytys](#1-allure-reportin-asennus).**

Alluren [dokumentaatiosta](https://allurereport.org/docs/pytest/#writing-tests) löytyy koodiesimerkkejä Alluren käytöstä pytest-ympäristössä. Tämä esimerkki havainnollistaa hyvin, miten paljon erilaista metadataa testeille pystyy lisäämään: 
```python
import allure

@allure.title("Test Authentication")
@allure.description("This test attempts to log into the website using a login and a password. Fails if any error happens.")
@allure.tag("NewUI", "Essentials", "Authentication")
@allure.severity(allure.severity_level.CRITICAL)
@allure.label("owner", "John Doe")
@allure.link("https://dev.example.com/", name="Website")
@allure.issue("AUTH-123")
@allure.testcase("TMS-456")
def test_authentication():
    ...
```

Testasin Allurea omassa projektissani:
```python
@allure.epic("Database tests")
@allure.suite("TC-01: Save data to database")
@allure.sub_suite("Save one item")
def test_save_one_document():
    ...
```

Kuvasta näkyy, miten testi organisoitiin raportissa käyttämieni `@allure`-annotaatioiden mukaisesti:

![Allure oma esimerkki selaimessa](kuvat/allure-report-esimerkki-2.png)


**Allure Report -raportin luominen**:

- Aja testit ja tallenna tulokset:
```
pytest --alluredir=allure-results
```
- Generoi raportti ja avaa se selaimessa:
```
allure generate allure-results --clean -o allure-report
allure open allure-report
```

**Historiatietojen seuraaminen Allurella**:

Allure Reportin avulla voi seurata testitulosten [historiatietoja](https://allurereport.org/docs/history-and-retries), mutta se ei tapahdu automaattisesti. Allure ei säilytä aiempien testiajojen tuloksia, ellei niitä siirretä talteen. Ideaalitilanteessa siirron voisi automatisoida esimerkiksi GitHub Actionsin kautta, mutta minulla ei ole juuri nyt aikaa perehtyä siihen. Tässä siis ohjeet historiatietojen siirtämiseen käsin:

> Poistot ja kopioinnit voi tehdä komentoriviltä alla olevien ohjeiden mukaan, mutta itse olen usein hoitanut ne suoraan VS Coden käyttöliittymässä, koska se on mielestäni kätevämpää.

1. Luo raportti normaalisti:
```
pytest --alluredir=allure-results
allure generate allure-results --clean -o allure-report
```
**Tarkista**, että `allure-report`-kansioon ilmestyi `history`-kansio.

2. Poista `allure-results`-kansio, jotta uusi data ei sekoitu edellisten ajojen kanssa:
```
rm -r allure-results  # Linux/macOS
del /s /q allure-results  # Windows
```

3. Aja testit uudelleen:
```
pytest --alluredir=allure-results
```

4. Kopioi edellisen ajon historiatiedot `allure-report`-kansiosta `allure-results`-kansioon (**HUOM.** tämä on tehtävä ennen uuden Allure-raportin generointia, muuten edellisen ajon tiedot menetetään):
```
cp -r allure-report/history allure-results/history  # Linux/macOS
xcopy /E /I allure-report\history allure-results\history  # Windows
```

5. Luo uusi raportti ja (halutessasi) avaa se selaimessa:
```
allure generate allure-results --clean -o allure-report
allure open allure-report
```
**Nyt raportin pitäisi näyttää myös edellisen ajon historiatiedot.**

> *HUOM*: Jos unohtaa kopioida historiatiedot jollakin ajokerralla, kyseisen ajon tiedot eivät tule mukaan seuraavaan raporttiin. Aiemmin siirretty historia säilyy, kunhan `history`-kansio kopioidaan `allure-results`-hakemistoon **ENNEN** uuden raportin generointia.

*Ohjeet historiatietojen poistamiseen ja kopioimiseen komentoriviltä generoitu ChatGPT:n avulla*.


Lähteet: 
- [Tulosten visualisointi](https://allurereport.org/docs/visual-analytics/)
- Testiraportin organisointi: [1](https://allurereport.org/docs/gettingstarted-navigation/#improving-navigation-in-your-test-report) & [2](https://allurereport.org/docs/gettingstarted-readability/)
- [Alluren käyttö pytestin kanssa](https://allurereport.org/docs/pytest/#getting-started-with-allure-pytest)
- [Historiatietojen seuraaminen](https://allurereport.org/docs/history-and-retries/#how-to-enable-history)

</details>

<p align="right"><a href="#seminaarityö-flask-backendin-testausta">⬆️</a></p>

## Testiympäristön pystytys

### 1. Allure Reportin asennus
Jotta Allure Reportia voi käyttää projektissa, se täytyy ensin asentaa omalle koneelle. Tämä käy ilmi esim. Allure Reportin [GitHub-sivulta](https://github.com/allure-framework/allure2). Suoritetaan asennus Alluren ohjeiden mukaan Windowsille:
1. Asennetaan [Scoop](https://scoop.sh/) (komentorivin asennusohjelma) PowerShellillä:
```
Set-ExecutionPolicy RemoteSigned -scope CurrentUser
Invoke-RestMethod -Uri https://get.scoop.sh | Invoke-Expression
```
2. Asennetaan Allure Scoopin avulla:
```
scoop install allure
```

### 2. Riippuvuuksien asentaminen
Seuraavaksi asennetaan testauksessa tarvittavat riippuvuudet Reddit Analyzeriin:
```
pip install pytest mongomock allure-pytest
```

- [pytest](https://docs.pytest.org/en/stable/) - Pythonin testikehys
- [mongomock](https://github.com/mongomock/mongomock) - tietokannan mockaukseen
- [allure-pytest](https://allurereport.org/docs/pytest/) - Alluren pytest-laajennos

### 3. Projektin alustaminen testaukselle
Luodaan testeille oma kansio nimeltä **tests** ja alustetaan se konfiguraatiotiedostolla nimeltä `conftest.py`, mukaillen Flaskin [tutoriaalia](https://flask.palletsprojects.com/en/stable/tutorial/tests/). Tiedostossa määritellään *fixturet*, jotka luovat sovelluksen testimoodissa.

Tutoriaalin esimerkki ei suoraan sovi meidän projektiimme, koska `app` luodaan hieman eri tavalla. Siksi joudumme soveltamaan vähän:
```python
@pytest.fixture
def app():
    """ Luo Flask-sovelluksen testauskonfiguraatioilla """
    app = create_app()
    app.config["TESTING"] = True
    app.config["JWT_SECRET_KEY"] = "test-secret"
    yield app

@pytest.fixture
def client(app):
    """ Mahdollistaa HTTP-kutsujen simuloinnin testeissä """
    return app.test_client()
```

Tutoriaalissa on käytössä eri tietokanta (SQlite) ja tietokanta määritellään eri tavalla kuin Reddit Analyzerissa, joten myös testitietokannan alustuksen suhteen täytyy soveltaa.

Reddit Analyzerissa tietokantayhteyttä hoidetaan *service*-kansion *db*-tiedostossa seuraavasti:
```python
def connect_db():
    try:
        uri = os.getenv("ATLAS_CONNECTION_STR")
        if not uri:
            raise ValueError("ATLAS_CONNECTION_STR is not set")
        
        client = MongoClient(uri)
        db = client.reddit
        return client, db
    except Exception as e:
        raise ConnectionError(f"Could not connect to database: {e}")
```
Sitten tätä funktiota kutsutaan tietokantaoperaatioita suorittavista funktiosta tähän tapaan:
```python
def save_data_to_database(data_to_save, collection):
    if not isinstance(data_to_save, (list, dict)):
        raise TypeError("Data to save must be a list or a dictionary")

    """ Yhdistetään tietokantaan apufunktion kautta """
    client, db = connect_db()
    coll = db[collection]

    try:
        if isinstance(data_to_save, list):
            coll.insert_many(data_to_save)
        elif isinstance(data_to_save, dict):
            coll.insert_one(data_to_save)
    except Exception as e:
        raise ConnectionError(f"Database error: {e}")
    finally:
        client.close()
```

Nyt katsoessa näitä funktioita mietin, onko tämä tapa tietokantayhteyden hoitamiseen aivan ideaali. Testauksen kannalta on haastavaa, että jokaisessa tietokantafunktiossa yritetään yhdistää oikeaan tietokantaan. Tästä sain idean, että voisin yrittää korvata `ATLAS_CONNECTION_STR`-arvon jotenkin niin, että yhdistetään oikean tietokannan sijasta testitietokantaan. En löytänyt tästä paljoakaan tietoa netistä, joten päädyin lopulta käyttämään apuna ChatGPT:tä. ChatGPT vinkkasi, että tähän voisi sopia pytestin [monkeypatch](https://docs.pytest.org/en/7.4.x/how-to/monkeypatch.html)-fixture, jonka metodeja voi käyttää **patchaamaan** tai korvaamaan arvoja tai toimintoja testausta varten. Tähän yhteyteen sopii monkeypatchin **setenv**-attribuutti. Lisätään testitietokanta `conftest`-tiedostoon:
```python
@pytest.fixture
def mock_db(monkeypatch):
    monkeypatch.setenv("ATLAS_CONNECTION_STR", "mongodb://mock")
    with mock.patch("app.services.db.MongoClient") as mock_client_class:
        mock_client = mongomock.MongoClient()
        mock_client_class.return_value = mock_client
        client, db = connect_db()
        yield client, db
```
Tässä siis korvataan `ATLAS_CONNECTION_STR` testaus-URIlla, ja `MongoClient` patchataan käyttämään `mongomock`-instanssia. Näin kaikki tietokantayhteydet testien aikana ohjautuvat testitietokantaan, eikä oikeaa tuotantotietokantaa käytetä vahingossa.

Jatkossa fixtureja voidaan hyödyntää testauksessa niin, että resurssi välitetään testifunktiolle funktion parametrina. Tässä on Flaskin [tutoriaalista](https://flask.palletsprojects.com/en/stable/tutorial/tests/#factory) esimerkki, jossa simuloidaan REST APIn toimintaa. Client-fixture välitetään funktion parametrina:
```python
def test_hello(client):
    response = client.get('/hello')
    assert response.data == b'Hello, World!'
```

<p align="right"><a href="#seminaarityö-flask-backendin-testausta">⬆️</a></p>


## Testien toteutus

Toteutin testit järjestyksessä suunnittelemieni testitapausten pohjalta niin, että yksi määritelty testivaihe vastaa yhtä testiä. Testien toteutuksessa käytin mallina Flaskin [testaustutoriaalia](https://flask.palletsprojects.com/en/stable/tutorial/tests), vaikkakin soveltaa sai aika paljon. Integroin **Allure Report**in mukaan alusta asti, ja sen käytön ohjenuorana toimi Alluren [dokumentaatio](https://allurereport.org/docs/pytest/#writing-tests), erityisesti osio **pytest**in kanssa käytöstä.

En ehtinyt suunnittelemaan testitapauksia kaikille backendin osa-alueille enkä täten myöskään testaamaan niitä, koska aika loppui kesken. Toteutin kuitenkin kaikki tässä työssä esitetyt [testitapaukset](#testitapaukset), ja ne kattavat sovelluksen kriittisimmät osat. Toteuttamatta jäi osa käyttäjähallintatesteistä sekä API-testit liittyen käyttäjän lisäominaisuuksiin (mm. tilaustoiminto).

Toteutin yhteensä **49 testiä**, ja ne jakautuivat seuraavasti:
| Osa-alue         | Testitapaukset | Testien lkm |
| ---------------- | -------------- | ----------- |
| Tietokanta       | TC-01 - TC-07  | 26          |
| REST API         | TC-08 - TC-12  | 15          |
| Käyttäjähallinta | TC-13 & TC-14  | 8           |

En näe tarpeelliseksi eritellä jokaisen testin toteutusta yksityiskohtaisesti tässä työssä. Valitsen 2-3 testitapausta per osa-alue, ja selitän niiden ratkaisut tarkemmin. Kaikki toteutetut testit ovat kuitenkin nähtävissä projektin [tests](https://github.com/ohjelmistoprojekti-ii-reddit-app/reddit-app-backend/tree/testing/tests)-kansiossa.

### Testien organisointi ja rakenne

Testit on järjestetty eri kansioihin osa-alueiden mukaan: tietokantatestit `database`-kansioon ja API-testit `rest_api`-kansioon. Käyttäjähallinta sijaitsee API-kansiossa, koska sitä hallitaan tavallisestikin APIn kautta.

Jokainen testiluokka vastaa yhtä testitapausta, ja Allure-annotaatiot on määritelty sekä luokka- että testitasolla. Tämä mahdollistaa testien järjestelmällisen tarkastelun Allure-raportin kautta, jossa testit näkyvät osa-alueittain, testitapauksittain ja kriittisyystason mukaan. Kuvaukset auttavat ymmärtämään, mistä testeissä on kyse.

Jokainen testifunktio alkaa `test_`-etuliitteellä, jotta pytest tunnistaa ja suorittaa sen automaattisesti.

*Esimerkki testien organisoinnista ja Allure-annotaatioista:*
```python
@allure.parent_suite("Database tests")
@allure.suite("TC-01: Save data to database")
@allure.severity(allure.severity_level.CRITICAL)
class TestSaveDataToDatabase:
    
    @allure.sub_suite("Save one item")
    @allure.description("Test saving a single document to the database, and verify it was saved correctly.")
    def test_save_one_document(self, mock_db):
        ...
```

### Esimerkkitestit

Seuraavaksi esitellään muutama esimerkkitesti kustakin testauksen osa-alueesta havainnollistamaan toteutusta ja testien rakennetta.

### Tietokantatestit

Suurin osa tietokantatesteistä on yksinkertaisia yksikkötestejä. Pyrin varmistamaan, että testit testaavat vain yhtä asiaa kerralla ja että testidata on hallittua ja tiivistä. Testeissä hyödynnetään [Testiympäristön pystytys](#testiympäristön-pystytys) -osiossa luotua `mock_db`-fixturea, joka mahdollistaa testitietokannan käytön.

### TC-02: Datan haku tietokannasta

<details>
    <summary><strong>Testattava funktio</strong></summary>

Tarkastelun alla on yleiskäyttöinen hakufunktio, joka mahdollistaa dokumenttien haun kokoelmasta filtterin avulla tai ilman. Jos filtteriä ei ole annettu, funktio palauttaa kaikki kokoelman dokumentit.

```python
def fetch_data_from_collection(collection, filter=None):
    if filter is not None and not isinstance(filter, dict):
        raise TypeError("Parameter 'filter' must be a dictionary or None")
    
    client, db = connect_db()
    try:
        coll = db[collection]
        data = list(coll.find(filter or {}))
        if not data:
            return []

        for item in data:
            item["_id"] = str(item["_id"])  # convert Mongo ObjectId to string
        return data
    except Exception as e:
        raise ConnectionError(f"Database error: {e}")
    finally:
        client.close()
```

</details>

● **Hae kaikki dokumentit:**

Tämä testi varmistaa perustoiminnallisuuden: jos kokoelmalle **ei anneta** filtteriä, funktion tulee palauttaa **kaikki** dokumentit. Testissä luodaan kaksi testidokumenttia ja tarkistetaan, että ne palautuvat samassa muodossa kuin tallennettiin. Lisäksi varmistetaan, että palautettu arvo on listamuotoinen, kuten funktion määrittely edellyttää.

```python
@allure.sub_suite("Fetch all documents")
@allure.description("Test fetching all documents from the database collection, and verify that the correct documents are returned as a list.")
def test_fetch_all_documents(self, mock_db):
    db = mock_db

    test_data = [
        { "title": "Test Post", "content": "This is a test post" },
        { "title": "Another Post", "content": "This is another post"}
    ]
    collection = "test_collection"

    db[collection].insert_many(test_data)
    fetched_data = fetch_data_from_collection(collection)

    assert isinstance(fetched_data, list)
    assert len(fetched_data) == 2
    assert fetched_data[0]["title"] == "Test Post"
    assert fetched_data[1]["title"] == "Another Post"
```

● **Hae dokumenttia filtterin kanssa:**

Tämä testi varmistaa, että funktio osaa rajata tulokset annetun **filtterin** perusteella. Testitietokantaan lisätään kaksi dokumenttia, joista vain toinen vastaa ehtoa.

```python
@allure.sub_suite("Fetch documents with filter")
@allure.description("Test fetching documents with a filter, and verify that the correct documents are returned as a list.")
def test_fetch_documents_using_filter(self, mock_db):
    db = mock_db

    test_data = [
        { "title": "Test Post", "content": "This is a test post" },
        { "title": "Another Post", "content": "This is another post"}
    ]
    collection = "test_collection"

    db[collection].insert_many(test_data)
    fetched_data = fetch_data_from_collection(collection, filter={"title": "Another Post"})

    assert len(fetched_data) == 1
    assert isinstance(fetched_data, list)
    assert fetched_data[0]["title"] == "Another Post"
```

● **Hae dokumenttia, jota ei ole olemassa:**

Tässä testissä tarkistetaan funktion käyttäytyminen tilanteessa, jossa mikään dokumentti **ei täytä** hakuehtoja. Odotettu tulos on tyhjä lista.

```python
@allure.sub_suite("Fetch non-existent document")
@allure.description("Test fetching a document that doesn't exist, and verify that an empty list is returned.")
def test_fetch_nonexistent_document(self, mock_db):
    db = mock_db

    test_data = [
        { "title": "Test Post", "content": "This is a test post" },
        { "title": "Another Post", "content": "This is another post"}
    ]
    collection = "test_collection"

    db[collection].insert_many(test_data)
    fetched_data = fetch_data_from_collection(collection, filter={"title": "Nonexistent"})

    assert len(fetched_data) == 0
    assert isinstance(fetched_data, list)
```

● **Hae dokumentit invalidin filtterin kanssa:**

Testattava funktio odottaa, että filtteri olisi sanakirja (`dict`). Tässä testissä varmistetaan virheenkäsittely tilanteessa, jossa käytetään **väärän tyyppistä** filtteriä.

```python
@allure.sub_suite("Fetch with invalid filter")
@allure.description("Test fetching documents with invalid filter, and verify that a TypeError is raised.")
def test_fetch_documents_with_invalid_filter_type(self, mock_db):
    collection = "test_collection"

    with pytest.raises(TypeError):
        fetch_data_from_collection(collection, filter="Invalid filter")
```

### TC-06: Postausmäärien laskeminen valitulla aikavälillä

<details>
    <summary><strong>Testattava funktio</strong></summary>

Tarkastelun alla on funktio, joka käyttää `MongoDB`:n aggregaatiopipelinea postausmäärien tilastojen laskemiseen tietokantaan tallennetun datan pohjalta. Huomioitavaa on, että funktio käyttää kovakoodattua kokoelmaa `posts` ja laskee tilastot aina edellistä päivästä alkaen.

```python
def get_post_numbers_by_timeperiod(subreddit, number_of_days):
    client, db = connect_db()
    collection = db["posts"]

    date_today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    min_date = date_today - timedelta(days=number_of_days)
    max_date = date_today

    # build aggregation pipeline
    pipeline = [
        # match with subreddit and timestamp >= min_date
        {"$match": {
            "subreddit": subreddit,
            "timestamp": {"$gte": min_date, "$lt": max_date}
        }},

        # pass docs to next stage in the pipeline
        {"$project": {
            "num_posts": 1,
            "day": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}}
        }},

        # group by day to get num_posts per day
        {"$group": {
            "_id": "$day",
            "posts_per_day": {"$sum": "$num_posts"}
        }},
        {"$sort": {"_id": 1}},

        #group by subreddit to push posts per day and total posts
        {"$group": {
            "_id": subreddit,
            "total_posts": {"$sum": "$posts_per_day"},
            "daily": {
                "$push": {
                    "day": "$_id",
                    "posts": "$posts_per_day"
                }
            }
        }},

    ]

    post_numbers = list(collection.aggregate(pipeline))
    client.close()
    
    return post_numbers
```
</details>

● **Laske postausmäärät validille subredditille:**

Tämä testi varmistaa, että postausmäärät lasketaan oikein annetulla aikavälillä. Testidataa talletetaan **usean päivän** ajalta, jonka jälkeen varmistetaan, että kaikki postaukset ovat mukana laskuissa. Testi olettaa, että nykyisen päivän tilastot ovat mukana. Koska testattava funktio laskee tilastot aina `datetime.now` -aikamääreen pohjalta, hyödynsin samaa logiikkaa myös testissä.

```python
@allure.sub_suite("Calculate post numbers for existing subreddit")
@allure.description("Test calculating post numbers for existing subreddit, and verify that the correct post count statistics are returned. Expects today's statistics to be included.")
def test_calculate_post_numbers_for_existing_subreddit(self, mock_db):
    db = mock_db

    # Ensure test data includes today's date
    current_date = datetime.now(timezone.utc)
    test_data =[
        { "subreddit": "example", "num_posts": 5, "timestamp": current_date },
        { "subreddit": "example", "num_posts": 10, "timestamp": (current_date - timedelta(days=1)) },
        { "subreddit": "example", "num_posts": 15, "timestamp": (current_date - timedelta(days=2)) },
    ]

    # Tested function uses hardcoded collection name "posts"
    db["posts"].insert_many(test_data)

    # High number_of_days to include all test data
    number_of_days = 10
    post_stats = get_post_numbers_by_timeperiod(subreddit="example", number_of_days=number_of_days)
    assert isinstance(post_stats, list)
    results = post_stats[0]

    current_date_str = current_date.strftime("%Y-%m-%d")

    current_date_found = False
    for stat in results["daily"]:
        if stat["day"] == current_date_str:
            current_date_found = True
            break

    assert current_date_found # Verify that today's statistics are included
    assert results["total_posts"] == 30 # 5 + 10 + 15
```

● **Laske postausmäärät subredditille, jota ei ole olemassa:**

Tämä testi tallettaa ensin tietokantaan dataa subredditille `example`, ja yrittää sen jälkeen laskea tilastoja subredditille `nonexistent`. Tämän avulla varmistetaan, että virheellisen subredditin käyttö käsitellään asianmukaisesti, eli funktio palauttaa tyhjän listan.

```python
@allure.sub_suite("Calculate post numbers for nonexistent subreddit")
@allure.description("Test calculating post numbers for nonexistent subreddit, and verify that an empty list is returned.")
def test_calculate_post_numbers_for_nonexistent_subreddit(self, mock_db):
    db = mock_db

    current_date = datetime.now(timezone.utc)
    test_data = [
        { "subreddit": "example", "num_posts": 5, "timestamp": current_date },
        { "subreddit": "example", "num_posts": 10, "timestamp": (current_date - timedelta(days=1)) },
    ]

    # Tested function uses hardcoded collection name "posts"
    db["posts"].insert_many(test_data)

    post_stats = get_post_numbers_by_timeperiod(subreddit="nonexistent", number_of_days=2)
    assert isinstance(post_stats, list)
    assert len(post_stats) == 0
```

● **Laske postausmäärät virheellisellä number_of_days -arvolla:**

Testi varmistaa asianmukaisen virheenkäsittelyn ja tarkistaa, että virheellisen `number_of_days`-arvon käyttö nostaa `ValueError`-virheen.

```python
@allure.sub_suite("Calculate post numbers with invalid number of days")
@allure.description("Test calculating post numbers with invalid number of days, and verify that a ValueError is raised.")
def test_calculate_post_numbers_with_invalid_number_of_days(self, mock_db):
    with pytest.raises(ValueError):
        get_post_numbers_by_timeperiod(subreddit="example", number_of_days=-2)
```

### REST API -testit

Valtaosa API-testeistä on integraatiotestejä, sillä useimmat endpointit ovat yhteydessä tietokantaan.

### TC-09: Hae trendianalyysin tulokset

<details>
    <summary><strong>Testattavat funktiot</strong></summary>

Tässä osiossa testataan `/topics/latest/<subreddit>` -endpointia sekä sen taustalla toimivaa tietokantafunktiota `get_latest_data_by_subreddit`. 

Huomioi, että tietokantahaku ja sen toiminnallisuus on testattu erikseen tietokantatesteissä (katso TC-05).

```python
# Endpoint
@topics_bp.route('/latest/<subreddit>', methods=['GET'])
def get_latest_posts_from_db(subreddit):
    data = get_latest_data_by_subreddit("posts", subreddit)

    if not data:
        return jsonify({"error": "No data found for this subreddit"}), 404
    
    return jsonify(data)

# Tietokantahaku
def get_latest_data_by_subreddit(collection, subreddit, type=None):
    if type is not None and type not in ["posts", "topics"]:
        raise ValueError("Parameter 'type' must be either 'posts', 'topics', or None")

    client, db = connect_db()
    
    try:
        coll = db[collection]
        latest_entry = coll.find_one({"subreddit": subreddit}, sort=[("timestamp", DESCENDING)])

        if not latest_entry:
            return []

        latest_timestamp = latest_entry["timestamp"]
        query = {"subreddit": subreddit, "timestamp": latest_timestamp}
        if type:
            query["type"] = type

        data = list(coll.find(query))

        for post in data:
            post["_id"] = str(post["_id"])  # convert Mongo ObjectId to string

        if data and 'topic_id' in data[0]:
            return sorted(data, key=lambda k: k['topic_id'])
        return data
    finally:
        client.close()
```

</details>

```python
@allure.sub_suite("Fetch topic analysis results with valid subreddit")
@allure.description("Test fetching latest topic analysis results with valid parameters, and verify the response includes correct data with latest timestamp.")
def test_fetch_topic_analysis_results_valid_params(self, client, mock_db):
    db = mock_db

    subreddit = "test"
    # Tested function uses 'posts' collection
    db["posts"].insert_many([
        {"subreddit": subreddit, "topic": "A", "timestamp": datetime(2025, 9, 1, 12, 0, tzinfo=timezone.utc)},
        {"subreddit": subreddit, "topic": "B", "timestamp": datetime(2025, 9, 1, 9, 0, tzinfo=timezone.utc)}
    ])

    response = client.get(f'/api/topics/latest/{subreddit}')
    assert response.status_code == 200

    data = response.get_json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]['topic'] == 'A' # Latest topic


@allure.sub_suite("Fetch topic analysis results with invalid subreddit")
@allure.description("Test fetching latest topic analysis results with invalid parameters, and verify that status 404 is returned.")
def test_fetch_topic_analysis_results_invalid_params(self, client, mock_db):
    db = mock_db

    # Tested function uses 'posts' collection
    db["posts"].insert_many([
        {"subreddit": "test", "topic": "A", "timestamp": datetime(2025, 9, 1, 12, 0, tzinfo=timezone.utc)},
        {"subreddit": "test", "topic": "B", "timestamp": datetime(2025, 9, 1, 9, 0, tzinfo=timezone.utc)}
    ])

    subreddit = "nonexistent"
    response = client.get(f'/api/topics/latest/{subreddit}')
    assert response.status_code == 404

    data = response.get_json()
    assert 'error' in data


@allure.sub_suite("Fetch topic analysis results and verify response content")
@allure.description("Test fetching latest topic analysis results and verify that response contains expected fields.")
def test_verify_topic_analysis_response_content(self, client, mock_db):
    db = mock_db

    subreddit = "test"
    # Tested function uses 'posts' collection
    db["posts"].insert_many([
        {"subreddit": subreddit, "topic": "A", "timestamp": datetime(2025, 9, 1, 15, 0, tzinfo=timezone.utc)},
        {"subreddit": subreddit, "topic": "B", "timestamp": datetime(2025, 9, 1, 10, 0, tzinfo=timezone.utc)}
    ])

    response = client.get(f'/api/topics/latest/{subreddit}')
    assert response.status_code == 200

    data = response.get_json()
    assert isinstance(data, list)
    assert len(data) == 1
    
    expected_fields = ["subreddit", "topic", "timestamp"]
    for field in expected_fields:
        assert field in data[0].keys()
```


<p align="right"><a href="#seminaarityö-flask-backendin-testausta">⬆️</a></p>



## GitHub Actions -integraatio

Seminaarityötä aloittaessani en pitänyt testien automatisointia **GitHub Actions**in avulla välttämättömänä, sillä projekti oli jo pitkällä ja jatkuvan integraation hyödyt olisivat korostuneet erityisesti kehityksen alkuvaiheessa. Testitulosten visualisointiin käytettävä `Allure Report` -työkalu osoittautui kuitenkin yllättävän monivaiheiseksi: se vaatii useita erillisiä asennuksia, ja raporttien tuottaminen edellyttää useiden komentojen ajamista oikeassa järjestyksessä. Lisäksi historiatiedot eivät päivity automaattisesti paikallisessa ajossa, vaan ne täytyy siirtää manuaalisesti testiajojen välillä.

Tämän vuoksi testien ja raporttien automatisointi osoittautui luontevaksi seuraavaksi askeleeksi - sen avulla kaikki pääsisivät tarkastelemaan ajantasaisia testituloksia ilman lisätyötä. Alluren dokumentaatiosta löytyi GitHub Actions -integraatiota varten kattavat [ohjeet](https://allurereport.org/docs/integrations-github/), joita seuraamalla automatisoin raportin julkaisun **GitHub Pages**iin.

### Workflown toteutus

Toteutin workflown seuraamalla Alluren esimerkkiä. Workflow suorittaa testit, generoi Allure-raportin ja julkaisee sen `gh-pages`-branchiin:

<details>
    <summary><strong>Workflow</strong></summary>
    
```yml
name: Run tests and publish report
on:
  push:
    branches:
      - main
      - testing
  workflow_dispatch:

jobs:
  test-and-report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Cache Python dependencies
        uses: actions/cache@v4
        continue-on-error: true
        with:
          path: ~/.cache/pip
          key: ${{ runner.os }}-pip-${{ hashFiles('**/requirements.txt') }}
          restore-keys: ${{ runner.os }}-pip-
          
      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Cache NLTK data
        uses: actions/cache@v4
        continue-on-error: true
        with:
          path: ~/nltk_data
          key: ${{ runner.os }}-nltk-${{ hashFiles('**/requirements.txt') }}
          restore-keys: ${{ runner.os }}-nltk-

      - name: Download NLTK data
        run: python -m nltk.downloader punkt punkt_tab vader_lexicon

      - name: Run tests
        run: pytest --alluredir=allure-results

      - name: Load test report history
        uses: actions/checkout@v4
        if: always()
        continue-on-error: true
        with:
          ref: gh-pages
          path: gh-pages

      - name: Build test report
        uses: simple-elf/allure-report-action@v1.13
        if: always()
        with:
          gh_pages: gh-pages
          allure_history: allure-history
          allure_results: allure-results

      - name: Publish test report
        uses: peaceiris/actions-gh-pages@v3
        if: always()
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          publish_branch: gh-pages
          publish_dir: allure-history
```

</details>

#### Keskeiset vaiheet
1. **Ympäristön pystytys:** Pythonin ja riippuvuuksien asentaminen ja cachettaminen
2. **Testien ajaminen:** pytest tuottaa testitulokset `allure-results`-kansioon
3. **Historiatietojen hakeminen:** edellisen ajon tulokset haetaan `gh-pages`-branchista
4. **Raportin luominen ja julkaisu:** testitulosten pohjalta generoidaan Allure-raportti ja se julkaistaan `gh-pages`-branchiin

Workflow suoritetaan automaattisesti aina, kun `main`- tai `testing`-branchiin pushataan uusi commit. Lisäksi workflown voi ajaa manuaalisesti `workflow dispatch`-toiminnolla.

### Repositorion konfiguraatiot
Repositorioon täytyy tehdä asetuksia, jotta workflow ja GitHub Pages -julkaisu saadaan toimimaan:

#### 1. GitHub Actions -luvat
Workflow tarvitsee luku- ja kirjoitusoikeudet `gh-pages`-branchiin. Oikeudet voi määrittää GitHubin **Settings → Actions → General → Workflow permissions** -valikossa:

![Workflown read-write luvat](kuvat/actions-read-write.png)
---

#### 2. GitHub Pages -asetukset
Testiraportin julkaisemiseksi GitHub Pagesin kautta tulee lähdebranchiksi valita `gh-pages`. Asetus löytyy GitHubin **Settings → Pages** -valikosta

![GitHub Pages lähde](kuvat/pages-konfiguraatio.png)
---

### Ongelmien ratkaisua 

Vaikka seurasin ohjeita tarkasti, Actions-prosessi ei mennyt ensimmäisellä ajokerralla läpi:

![Actions virhe](kuvat/actions-virhe.png)

Pienen selvittelyn jälkeen kävi ilmi, että virhe johtui *allure-report-action*in väärästä versiosta (`v1.7`). Tästä oli [issue](https://github.com/simple-elf/allure-report-action/issues/72) actionin repositoriossa. Vinkkien avulla päivitin version uusimpaan versioon (`v1.13`), julkaisu onnistui ja raporttia pääsi viimein tarkastelemaan suoraan selaimessa:
- [GitHub Pages](https://ohjelmistoprojekti-ii-reddit-app.github.io/reddit-app-backend)


<p align="right"><a href="#seminaarityö-flask-backendin-testausta">⬆️</a></p>


## Lähteet
- https://flask.palletsprojects.com/en/stable/testing/
- https://dev.to/reritom/unit-testing-pymongo-flask-applications-with-mongomock-and-patches-1m23
- https://flask.palletsprojects.com/en/stable/tutorial/tests/
- https://www.mongodb.com/docs/atlas/
- https://docs.pytest.org/en/stable/
- https://github.com/mongomock/mongomock
- https://docs.github.com/en/actions
- https://allurereport.org/docs/
- Kasurinen, J. 2013. Ohjelmistotestauksen käsikirja. 1. painos. Docendo. Jyväskylä.


## Tekoälyn käyttö työn toteutuksessa

Olen hyödyntänyt tekoälyä, kuten ChatGPT:tä, tekstien muotoilun apuna. Kirjoitan ensin kappaleen itse ja tarvittaessa pyydän tekoälyä ehdottamaan vaihtoehtoisia muotoiluja, joista sitten yhdistän osia omaan tekstiini. Sisällön olen kuitenkin tuottanut itse, enkä käytä tekoälyä tekstin suoraan generointiin.

Käytin tekoälyä apuna myös testiympäristön suunnittelussa ja pystyttämisessä, eli esim. mitä kirjastoja täytyy ladata ja miten alustaa sovellus testausta varten. Minun oli vaikea aluksi ymmärtää, miten pytestin fixtureja käytetään Flask-sovelluksen käynnistämiseen testaustilassa, ja tekoäly oli hyvä apu tässä. Tekoäly auttoi myös pääsemään alkuun mongomockin kanssa.
