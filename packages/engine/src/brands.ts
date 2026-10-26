/**
 * Commonly impersonated organisations.
 *
 * `slugs` are the names attackers hide in domains; the first one is the label the
 * brand uses under country codes (paypal.ca). `domains` are domains the brand
 * really sends from. Consumer mailbox domains (outlook.com, gmail.com, icloud.com)
 * are deliberately absent: anyone can open an account there, and the brand's
 * own notices never come from them.
 */
export interface Brand {
  name: string;
  slugs: string[];
  domains: string[];
  /** Domain endings that always belong to the brand, e.g. ".gov.br" for Brazil's government. */
  suffixes?: string[];
  /** Where to go instead of clicking: the address a reader can type themselves. */
  home: string;
  /** Patterns that mean an email claims to come from this brand. */
  mentions: RegExp[];
}

const brand = (name: string, slugs: string[], domains: string[], mentions: RegExp[], suffixes?: string[]): Brand => ({
  name,
  slugs,
  domains,
  home: domains[0]!,
  mentions,
  ...(suffixes && { suffixes }),
});

export const BRANDS: Brand[] = [
  brand("PayPal", ["paypal"], ["paypal.com", "paypal.me"], [/\bpay ?pal\b/i]),
  brand(
    "Microsoft",
    ["microsoft", "office365", "microsoft365", "onedrive", "sharepoint", "m365", "o365"],
    ["microsoft.com", "microsoftonline.com", "office.com", "office365.com", "microsoft365.com", "sharepointonline.com", "onedrive.com", "azure.com", "msn.com", "skype.com", "xbox.com"],
    [/\bmicrosoft\b/i, /\boffice ?365\b/i, /\bm365\b/i, /\bo365\b/i, /\bone ?drive\b/i, /\bsharepoint\b/i, /\boutlook (team|web|support|account|security|admin|mail)\b/i],
  ),
  brand(
    "Apple",
    ["apple", "icloud", "itunes", "appleid"],
    ["apple.com", "itunes.com"],
    [/^apple$/i, /\bapple ?(id|support|pay|account|store|care|billing|services|music)\b/i, /\bicloud\b/i, /\bitunes\b/i, /\bapp store\b/i],
  ),
  brand(
    "Amazon",
    ["amazon", "amzn", "primevideo"],
    ["amazon.com", "amazon.ca", "amazon.co.uk", "amazon.de", "amazon.com.au", "amazonaws.com", "primevideo.com"],
    [/\bamazon\b/i, /\bprime video\b/i],
  ),
  brand("Google", ["google", "gmail", "youtube"], ["google.com", "youtube.com"], [/\bgoogle\b/i, /\bgmail\b/i, /\byoutube\b/i]),
  brand("Netflix", ["netflix"], ["netflix.com"], [/\bnetflix\b/i]),
  brand("DocuSign", ["docusign"], ["docusign.com", "docusign.net"], [/\bdocu ?sign\b/i]),
  brand("Dropbox", ["dropbox"], ["dropbox.com", "dropboxmail.com"], [/\bdropbox\b/i]),
  brand("Adobe", ["adobe", "acrobat"], ["adobe.com", "adobesign.com", "acrobat.com"], [/\badobe\b/i, /\bacrobat\b/i]),
  brand("LinkedIn", ["linkedin"], ["linkedin.com"], [/\blinked ?in\b/i]),
  brand("Facebook", ["facebook"], ["facebook.com", "facebookmail.com", "meta.com", "fb.com"], [/\bfacebook\b/i, /\bmeta (support|business|verified|pay)\b/i]),
  brand("Instagram", ["instagram"], ["instagram.com", "mail.instagram.com"], [/\binstagram\b/i]),
  brand("WhatsApp", ["whatsapp"], ["whatsapp.com"], [/\bwhats ?app\b/i]),
  brand("DHL", ["dhl"], ["dhl.com", "dhl.de", "dhl.ca"], [/\bdhl\b/i]),
  brand("FedEx", ["fedex"], ["fedex.com"], [/\bfed ?ex\b/i]),
  brand("UPS", ["ups"], ["ups.com"], [/\bUPS\b/]),
  brand("USPS", ["usps"], ["usps.com", "usps.gov"], [/\busps\b/i, /\bpostal service\b/i]),
  brand("Canada Post", ["canadapost", "postescanada"], ["canadapost.ca", "canadapost-postescanada.ca", "postescanada.ca"], [/\bcanada post\b/i, /\bpostes canada\b/i]),
  brand("Purolator", ["purolator"], ["purolator.com"], [/\bpurolator\b/i]),
  brand("Interac", ["interac", "etransfer"], ["interac.ca"], [/\binterac\b/i, /\be-?transfer\b/i]),
  brand("the Canada Revenue Agency", ["cra", "canadarevenue"], ["canada.ca", "cra-arc.gc.ca"], [/\bcanada revenue agency\b/i, /\bCRA\b/]),
  brand("RBC", ["rbc", "royalbank", "rbcroyalbank"], ["rbc.com", "rbcroyalbank.com"], [/\bRBC\b/, /\broyal bank\b/i]),
  brand("TD Bank", ["tdbank", "tdcanadatrust", "td"], ["td.com", "tdbank.com", "tdcanadatrust.com"], [/\bTD (bank|canada trust|easyweb|alerts)\b/i]),
  brand("Scotiabank", ["scotiabank", "scotia"], ["scotiabank.com"], [/\bscotia ?bank\b/i]),
  brand("BMO", ["bmo"], ["bmo.com"], [/\bBMO\b/]),
  brand("CIBC", ["cibc"], ["cibc.com"], [/\bCIBC\b/]),
  brand("Desjardins", ["desjardins"], ["desjardins.com"], [/\bdesjardins\b/i]),
  brand("Chase", ["chase", "jpmorgan"], ["chase.com", "jpmorgan.com", "jpmorganchase.com"], [/^chase$/i, /\bchase (bank|online|alerts|card services|security)\b/i, /\bjp ?morgan\b/i]),
  brand("Wells Fargo", ["wellsfargo"], ["wellsfargo.com", "wf.com"], [/\bwells fargo\b/i]),
  brand("Bank of America", ["bankofamerica", "bofa"], ["bankofamerica.com"], [/\bbank of america\b/i]),
  brand("American Express", ["americanexpress", "amex"], ["americanexpress.com", "aexp.com"], [/\bamerican express\b/i, /\bamex\b/i]),
  brand("Coinbase", ["coinbase"], ["coinbase.com"], [/\bcoinbase\b/i]),
  brand("Binance", ["binance"], ["binance.com"], [/\bbinance\b/i]),
  brand("MetaMask", ["metamask"], ["metamask.io"], [/\bmeta ?mask\b/i]),
  brand("Steam", ["steampowered", "steamcommunity", "steam"], ["steampowered.com", "steamcommunity.com"], [/\bsteam (support|community|guard|account)\b/i]),
  brand("eBay", ["ebay"], ["ebay.com", "ebay.ca", "ebay.co.uk"], [/\bebay\b/i]),
  brand("Walmart", ["walmart"], ["walmart.com", "walmart.ca"], [/\bwalmart\b/i]),
  brand("Costco", ["costco"], ["costco.com", "costco.ca"], [/\bcostco\b/i]),
  brand("Geek Squad", ["geeksquad"], ["geeksquad.com", "bestbuy.com"], [/\bgeek ?squad\b/i]),
  brand("Norton", ["norton", "nortonlifelock"], ["norton.com", "nortonlifelock.com"], [/\bnorton\b/i]),
  brand("McAfee", ["mcafee"], ["mcafee.com"], [/\bmc ?afee\b/i]),
  brand("Venmo", ["venmo"], ["venmo.com"], [/\bvenmo\b/i]),
  brand("Cash App", ["cashapp"], ["cash.app", "squareup.com"], [/\bcash ?app\b/i]),
  brand("Zelle", ["zelle", "zellepay"], ["zellepay.com"], [/\bzelle\b/i]),
  brand("Spotify", ["spotify"], ["spotify.com"], [/\bspotify\b/i]),
  brand("Uber", ["uber"], ["uber.com"], [/\buber\b/i]),
  brand("Airbnb", ["airbnb"], ["airbnb.com", "airbnb.ca"], [/\bairbnb\b/i]),
  brand("Zoom", ["zoom"], ["zoom.us", "zoom.com"], [/\bzoom (meeting|video|support|account)\b/i, /^zoom$/i]),
  brand("Intuit", ["intuit", "quickbooks", "turbotax"], ["intuit.com", "quickbooks.com", "turbotax.com"], [/\bintuit\b/i, /\bquick ?books\b/i, /\bturbo ?tax\b/i]),
  brand("the IRS", ["irs"], ["irs.gov"], [/\bIRS\b/, /\binternal revenue service\b/i]),
  brand("Rogers", ["rogers"], ["rogers.com"], [/\brogers (wireless|communications|bank|support|billing)\b/i]),
  brand("Bell", ["bell"], ["bell.ca"], [/\bbell (canada|mobility|aliant|billing)\b/i]),
  brand("Telus", ["telus"], ["telus.com"], [/\btelus\b/i]),
  brand("Roblox", ["roblox"], ["roblox.com"], [/\broblox\b/i]),
  brand("Discord", ["discord"], ["discord.com", "discordapp.com"], [/\bdiscord\b/i]),

  // Brazil
  brand("Correios", ["correios"], ["correios.com.br"], [/\bcorreios\b/i]),
  brand("Detran", ["detran"], ["gov.br"], [/\bdetran\b/i], [".gov.br"]),
  brand("Receita Federal", ["receita", "receitafederal"], ["gov.br"], [/\breceita federal\b/i], [".gov.br"]),
  brand("gov.br", ["govbr"], ["gov.br"], [/\bgov\.br\b/i, /\bgoverno federal\b/i], [".gov.br"]),
  brand("Caixa", ["caixa"], ["caixa.gov.br"], [/\bcaixa (econ[ôo]mica|tem)\b/i, /^caixa$/i], [".caixa.gov.br"]),
  brand("Banco do Brasil", ["bancodobrasil", "bb"], ["bb.com.br"], [/\bbanco do brasil\b/i]),
  brand("Itaú", ["itau"], ["itau.com.br"], [/\bita[úu]\b/i]),
  brand("Bradesco", ["bradesco"], ["bradesco.com.br"], [/\bbradesco\b/i]),
  brand("Santander", ["santander"], ["santander.com.br", "santander.com", "santander.es", "santander.co.uk"], [/\bsantander\b/i]),
  brand("Nubank", ["nubank"], ["nubank.com.br", "nu.com.mx"], [/\bnubank\b/i]),
  brand("Mercado Livre", ["mercadolivre", "mercadolibre", "mercadopago"], ["mercadolivre.com.br", "mercadolibre.com", "mercadopago.com.br", "mercadopago.com"], [/\bmercado (livre|libre|pago)\b/i]),
  brand("Magalu", ["magalu", "magazineluiza"], ["magazineluiza.com.br", "magalu.com"], [/\bmagalu\b/i, /\bmagazine luiza\b/i]),
  brand("Americanas", ["americanas"], ["americanas.com.br"], [/\bamericanas\b/i]),
  brand("Shopee", ["shopee"], ["shopee.com.br", "shopee.com"], [/\bshopee\b/i]),
  brand("Serasa", ["serasa"], ["serasa.com.br"], [/\bserasa\b/i]),
  brand("PicPay", ["picpay"], ["picpay.com"], [/\bpicpay\b/i]),

  // Germany, Austria, Switzerland
  brand("Deutsche Post", ["deutschepost"], ["deutschepost.de", "dhl.de"], [/\bdeutsche post\b/i]),
  brand("Telekom", ["telekom"], ["telekom.de", "telekom.com", "t-online.de"], [/\btelekom\b/i]),
  brand("Sparkasse", ["sparkasse"], ["sparkasse.de"], [/\bsparkasse\b/i]),
  brand("Volksbank", ["volksbank"], ["vr.de", "volksbank.de"], [/\bvolksbank\b/i, /\braiffeisenbank\b/i]),
  brand("Postbank", ["postbank"], ["postbank.de"], [/\bpostbank\b/i]),
  brand("Commerzbank", ["commerzbank"], ["commerzbank.de", "commerzbank.com"], [/\bcommerzbank\b/i]),
  brand("Deutsche Bank", ["deutschebank"], ["deutsche-bank.de", "db.com"], [/\bdeutsche bank\b/i]),
  brand("ING", ["ing"], ["ing.de", "ing.com", "ing.nl", "ing.be"], [/^ing( bank| diba)?$/i, /\bing-?diba\b/i]),
  brand("N26", ["n26"], ["n26.com"], [/\bn26\b/i]),
  brand("REWE", ["rewe"], ["rewe.de"], [/\brewe\b/i]),
  brand("EDEKA", ["edeka"], ["edeka.de"], [/\bedeka\b/i]),
  brand("Lidl", ["lidl"], ["lidl.de", "lidl.com", "lidl.co.uk"], [/\blidl\b/i]),
  brand("Aldi", ["aldi"], ["aldi-nord.de", "aldi-sued.de", "aldi.com", "aldi.us", "aldi.co.uk"], [/\baldi\b/i]),
  brand("Netto", ["netto"], ["netto-online.de", "netto.de"], [/\bnetto\b/i]),
  brand("Kaufland", ["kaufland"], ["kaufland.de"], [/\bkaufland\b/i]),
  brand("Otto", ["otto"], ["otto.de"], [/^otto$/i, /\botto versand\b/i]),
  brand("Zalando", ["zalando"], ["zalando.de", "zalando.com"], [/\bzalando\b/i]),
  brand("MediaMarkt", ["mediamarkt"], ["mediamarkt.de"], [/\bmedia ?markt\b/i]),
  brand("ADAC", ["adac"], ["adac.de"], [/\badac\b/i]),
  brand("Europa-Park", ["europapark"], ["europapark.de"], [/\beuropa-? ?park\b/i]),
  brand("Vodafone", ["vodafone"], ["vodafone.de", "vodafone.com", "vodafone.co.uk"], [/\bvodafone\b/i]),
  brand("ELSTER", ["elster"], ["elster.de"], [/\belster\b/i, /\bfinanzamt\b/i]),

  // Spain, France, Netherlands, Italy, UK
  brand("Correos", ["correos"], ["correos.es"], [/^correos$/i, /\bcorreos (express|espa[ñn]a)\b/i]),
  brand("BBVA", ["bbva"], ["bbva.es", "bbva.com", "bbva.mx"], [/\bbbva\b/i]),
  brand("CaixaBank", ["caixabank"], ["caixabank.es"], [/\bcaixabank\b/i]),
  brand("Bizum", ["bizum"], ["bizum.es"], [/\bbizum\b/i]),
  brand("La Poste", ["laposte", "colissimo", "chronopost"], ["laposte.fr", "colissimo.fr", "chronopost.fr", "laposte.net"], [/\bla poste\b/i, /\bcolissimo\b/i, /\bchronopost\b/i]),
  brand("Ameli", ["ameli"], ["ameli.fr", "assurance-maladie.fr"], [/\bameli\b/i, /\bassurance maladie\b/i]),
  brand("the French tax office", ["impots"], ["impots.gouv.fr"], [/\bimp[ôo]ts\.gouv\b/i, /\bdgfip\b/i], [".gouv.fr"]),
  brand("Crédit Agricole", ["creditagricole"], ["credit-agricole.fr", "credit-agricole.com"], [/\bcr[ée]dit agricole\b/i]),
  brand("PostNL", ["postnl"], ["postnl.nl"], [/\bpostnl\b/i]),
  brand("DigiD", ["digid"], ["digid.nl"], [/\bdigid\b/i, /\bbelastingdienst\b/i], [".overheid.nl", ".belastingdienst.nl"]),
  brand("Rabobank", ["rabobank"], ["rabobank.nl", "rabobank.com"], [/\brabobank\b/i]),
  brand("ABN AMRO", ["abnamro"], ["abnamro.nl", "abnamro.com"], [/\babn ?amro\b/i]),
  brand("bol.com", ["bol"], ["bol.com"], [/\bbol\.com\b/i]),
  brand("Poste Italiane", ["poste", "posteitaliane"], ["poste.it", "posteitaliane.it"], [/\bposte italiane\b/i, /\bpostepay\b/i]),
  brand("Intesa Sanpaolo", ["intesasanpaolo"], ["intesasanpaolo.com"], [/\bintesa ?sanpaolo\b/i]),
  brand("UniCredit", ["unicredit"], ["unicredit.it", "unicredit.eu"], [/\bunicredit\b/i]),
  brand("Royal Mail", ["royalmail"], ["royalmail.com", "royalmail.co.uk"], [/\broyal mail\b/i]),
  brand("Evri", ["evri", "hermes"], ["evri.com", "myhermes.co.uk"], [/\bevri\b/i]),
  brand("HMRC", ["hmrc"], ["gov.uk"], [/\bhmrc\b/i, /\bhm revenue\b/i, /\bdvla\b/i], [".gov.uk"]),
  brand("the NHS", ["nhs"], ["nhs.uk", "nhs.net"], [/\bnhs\b/i]),
  brand("TV Licensing", ["tvlicensing"], ["tvlicensing.co.uk"], [/\btv licen[cs]ing\b/i]),
  brand("Barclays", ["barclays"], ["barclays.co.uk", "barclays.com"], [/\bbarclays\b/i]),
  brand("HSBC", ["hsbc"], ["hsbc.co.uk", "hsbc.com", "hsbc.ca"], [/\bhsbc\b/i]),
  brand("Lloyds", ["lloyds", "lloydsbank"], ["lloydsbank.com", "lloydsbank.co.uk"], [/\blloyds( bank)?\b/i]),
  brand("NatWest", ["natwest"], ["natwest.com"], [/\bnatwest\b/i]),
  brand("Monzo", ["monzo"], ["monzo.com"], [/\bmonzo\b/i]),
  brand("Revolut", ["revolut"], ["revolut.com"], [/\brevolut\b/i]),
  brand("Wise", ["transferwise"], ["wise.com", "transferwise.com"], [/^wise$/i, /\btransferwise\b/i]),

  // North America and global
  brand("AT&T", ["att"], ["att.com", "att.net"], [/\bat&t\b/i, /\bat ?& ?t\b/i]),
  brand("Verizon", ["verizon"], ["verizon.com", "verizonwireless.com"], [/\bverizon\b/i]),
  brand("T-Mobile", ["tmobile"], ["t-mobile.com"], [/\bt-?mobile\b/i]),
  brand("Spectrum", ["spectrum"], ["spectrum.com", "spectrum.net", "charter.com"], [/^spectrum$/i, /\bspectrum (internet|mobile|billing)\b/i]),
  brand("Xfinity", ["xfinity", "comcast"], ["xfinity.com", "comcast.net", "comcast.com"], [/\bxfinity\b/i, /\bcomcast\b/i]),
  brand("USAA", ["usaa"], ["usaa.com"], [/\busaa\b/i]),
  brand("Fidelity", ["fidelity"], ["fidelity.com"], [/\bfidelity (investments|account)\b/i]),
  brand("Robinhood", ["robinhood"], ["robinhood.com"], [/\brobinhood\b/i]),
  brand("Kraken", ["kraken"], ["kraken.com"], [/\bkraken\b/i]),
  brand("Crypto.com", ["cryptocom"], ["crypto.com"], [/\bcrypto\.com\b/i]),
  brand("Ledger", ["ledger"], ["ledger.com"], [/\bledger (live|wallet|nano|support)\b/i, /^ledger$/i]),
  brand("Trezor", ["trezor"], ["trezor.io"], [/\btrezor\b/i]),
  brand("Trust Wallet", ["trustwallet"], ["trustwallet.com"], [/\btrust ?wallet\b/i]),
  brand("OpenSea", ["opensea"], ["opensea.io"], [/\bopensea\b/i]),
  brand("Home Depot", ["homedepot"], ["homedepot.com"], [/\bhome depot\b/i]),
  brand("Lowe's", ["lowes"], ["lowes.com"], [/\blowe'?s\b/i]),
  brand("Ace Hardware", ["acehardware"], ["acehardware.com"], [/\bace hardware\b/i]),
  brand("Target", ["target"], ["target.com"], [/^target$/i, /\btarget (circle|gift ?card|rewards)\b/i]),
  brand("Kohl's", ["kohls"], ["kohls.com"], [/\bkohl'?s\b/i]),
  brand("Best Buy", ["bestbuy"], ["bestbuy.com", "bestbuy.ca"], [/\bbest ?buy\b/i]),
  brand("Starbucks", ["starbucks"], ["starbucks.com"], [/\bstarbucks\b/i]),
  brand("McDonald's", ["mcdonalds"], ["mcdonalds.com"], [/\bmcdonald'?s\b/i]),
  brand("Hilton", ["hilton"], ["hilton.com", "hiltonhonors.com"], [/\bhilton\b/i]),
  brand("Marriott", ["marriott"], ["marriott.com"], [/\bmarriott\b/i]),
  brand("Booking.com", ["booking"], ["booking.com"], [/\bbooking\.com\b/i]),
  brand("Expedia", ["expedia"], ["expedia.com", "expediamail.com"], [/\bexpedia\b/i]),
  brand("Delta", ["delta"], ["delta.com"], [/\bdelta (air ?lines|skymiles)\b/i]),
  brand("United Airlines", ["united"], ["united.com"], [/\bunited airlines\b/i, /\bmileageplus\b/i]),
  brand("American Airlines", ["americanairlines", "aa"], ["aa.com"], [/\bamerican airlines\b/i, /\baadvantage\b/i]),
  brand("Disney+", ["disneyplus", "disney"], ["disneyplus.com", "disney.com"], [/\bdisney ?(\+|plus)\b/i]),
  brand("Max", ["hbomax"], ["max.com", "hbomax.com"], [/\bhbo ?max\b/i]),
  brand("Samsung", ["samsung"], ["samsung.com"], [/\bsamsung\b/i]),
  brand("Avast", ["avast"], ["avast.com"], [/\bavast (antivirus|security|premium|one|support)\b/i, /^avast$/i]),
  brand("Kaspersky", ["kaspersky"], ["kaspersky.com"], [/\bkaspersky\b/i]),
  brand("Bitdefender", ["bitdefender"], ["bitdefender.com"], [/\bbitdefender\b/i]),
  brand("WeTransfer", ["wetransfer"], ["wetransfer.com"], [/\bwe ?transfer\b/i]),
  brand("Webex", ["webex"], ["webex.com", "cisco.com"], [/\bwebex\b/i]),
  brand("Slack", ["slack"], ["slack.com"], [/^slack$/i]),
  brand("Telegram", ["telegram"], ["telegram.org"], [/\btelegram\b/i]),
  brand("TikTok", ["tiktok"], ["tiktok.com"], [/\btik ?tok\b/i]),
  brand("X", ["twitter"], ["x.com", "twitter.com"], [/\btwitter\b/i]),
  brand("Temu", ["temu"], ["temu.com"], [/\btemu\b/i]),
  brand("AliExpress", ["aliexpress", "alibaba"], ["aliexpress.com", "alibaba.com"], [/\bali ?express\b/i, /\balibaba\b/i]),
  brand("Shein", ["shein"], ["shein.com"], [/\bshein\b/i]),
  brand("Etsy", ["etsy"], ["etsy.com"], [/\betsy\b/i]),
  brand("Dewalt", ["dewalt"], ["dewalt.com"], [/\bdewalt\b/i]),
  brand("Stanley", ["stanley1913"], ["stanley1913.com"], [/\bstanley (cup|tumbler|quencher)\b/i]),
  brand("Yeti", ["yeti"], ["yeti.com"], [/\byeti (cooler|tumbler|rambler)\b/i]),
  brand("Social Security", ["ssa"], ["ssa.gov"], [/\bsocial security administration\b/i], [".gov"]),
];

/** Free mailbox providers: anyone can create an account in minutes. */
export const FREE_MAIL = new Set([
  "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "yahoo.ca",
  "yahoo.co.uk", "ymail.com", "aol.com", "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com", "pm.me",
  "gmx.com", "gmx.net", "mail.com", "yandex.com", "yandex.ru", "zoho.com", "tutanota.com", "tuta.io", "qq.com",
  "163.com", "rediffmail.com",
]);

/** Display names that claim an organisational role. */
export const ROLE_NAME =
  /\b(admin(istrator)?|it (support|department|team|desk)|help ?desk|service ?desk|payroll|human resources|hr (team|department)|accounts? (payable|receivable)|billing (team|department)|security (team|alert)|post ?master|mail(box)? (administrator|delivery|admin)|web ?master|ceo|cfo|president|director)\b/i;

export function brandsMentionedIn(text: string): Brand[] {
  return BRANDS.filter((b) => b.mentions.some((re) => re.test(text)));
}
