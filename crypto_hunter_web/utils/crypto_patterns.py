# crypto_hunter_web/utils/crypto_patterns.py - COMPLETE CRYPTO PATTERN DETECTION

import logging
import re
from typing import Dict, Any

logger = logging.getLogger(__name__)


class CryptoPatterns:
    """Comprehensive cryptocurrency and cryptographic pattern detection"""

    def __init__(self):
        """Initialize crypto pattern detector with compiled patterns"""
        self._compile_patterns()
        self._load_known_addresses()
        self._load_crypto_keywords()

    def _compile_patterns(self):
        """Compile regex patterns for performance"""

        # Bitcoin address patterns
        self.bitcoin_legacy = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
        self.bitcoin_segwit = re.compile(r'\bbc1[a-z0-9]{39,59}\b', re.I)

        # Ethereum address patterns
        self.ethereum_address = re.compile(r'\b0x[a-fA-F0-9]{40}\b')

        # Other cryptocurrency addresses
        self.litecoin_address = re.compile(r'\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b')
        self.dogecoin_address = re.compile(r'\bD{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}\b')
        self.monero_address = re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b')
        self.zcash_address = re.compile(r'\bt1[a-zA-Z0-9]{33}\b')
        self.ripple_address = re.compile(r'\br[a-zA-Z0-9]{24,34}\b')

        # Private key patterns
        self.private_key_hex = re.compile(r'\b[a-fA-F0-9]{64}\b')
        self.private_key_wif = re.compile(r'\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b')

        # Cryptographic patterns
        self.pem_begin = re.compile(r'-----BEGIN [A-Z ]+-----')
        self.pem_end = re.compile(r'-----END [A-Z ]+-----')
        self.ssh_key = re.compile(r'ssh-[a-z0-9]+ [A-Za-z0-9+/=]+', re.I)
        self.pgp_block = re.compile(r'-----BEGIN PGP [A-Z ]+-----.*?-----END PGP [A-Z ]+-----', re.DOTALL)

        # Base64 patterns (potential keys/certificates)
        self.base64_long = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')

        # Hash patterns
        self.md5_hash = re.compile(r'\b[a-fA-F0-9]{32}\b')
        self.sha1_hash = re.compile(r'\b[a-fA-F0-9]{40}\b')
        self.sha256_hash = re.compile(r'\b[a-fA-F0-9]{64}\b')
        self.sha512_hash = re.compile(r'\b[a-fA-F0-9]{128}\b')

        # Mnemonic seed phrases
        self.mnemonic_pattern = re.compile(
            r'\b(?:abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse|access|'
            r'accident|account|accuse|achieve|acid|acoustic|acquire|across|act|action|actor|'
            r'actual|adapt|add|addict|address|adjust|admit|adult|advance|advice|aerobic|affair|'
            r'afford|afraid|again|age|agent|agree|ahead|aim|air|airport|aisle|alarm|album|'
            r'alcohol|alert|alien|all|alley|allow|almost|alone|alpha|already|also|alter|'
            r'always|amateur|amazing|among|amount|amused|analyst|anchor|ancient|anger|angle|'
            r'angry|animal|ankle|announce|annual|another|answer|antenna|antique|anxiety|any|'
            r'apart|apology|appear|apple|approve|april|arch|arctic|area|arena|argue|arm|'
            r'armed|armor|army|around|arrange|arrest|arrive|arrow|art|artefact|artist|artwork|'
            r'ask|aspect|assault|asset|assist|assume|asthma|athlete|atom|attack|attend|'
            r'attitude|attract|auction|audit|august|aunt|author|auto|autumn|average|avocado|'
            r'avoid|awake|aware|away|awesome|awful|awkward|axis|baby|bachelor|bacon|badge|bag|'
            r'balance|balcony|ball|bamboo|banana|banner|bar|barely|bargain|barrel|base|basic|'
            r'basket|battle|beach|bean|beauty|because|become|beef|before|begin|behave|behind|'
            r'believe|below|belt|bench|benefit|best|betray|better|between|beyond|bicycle|bid|'
            r'bike|bind|biology|bird|birth|bitter|black|blade|blame|blanket|blast|bleak|'
            r'bless|blind|blood|blossom|blow|blue|blur|blush|board|boat|body|boil|bomb|bone|'
            r'bonus|book|boost|border|boring|borrow|boss|bottom|bounce|box|boy|bracket|brain|'
            r'brand|brass|brave|bread|breeze|brick|bridge|brief|bright|bring|brisk|broccoli|'
            r'broken|bronze|broom|brother|brown|brush|bubble|buddy|budget|buffalo|build|bulb|'
            r'bulk|bullet|bundle|bunker|burden|burger|burst|bus|business|busy|butter|buyer|'
            r'buzz|cabbage|cabin|cable|cactus|cage|cake|call|calm|camera|camp|can|canal|'
            r'cancel|candy|cannon|canoe|canvas|canyon|capable|capital|captain|car|carbon|card|'
            r'care|career|careful|careless|cargo|carpet|carry|cart|case|cash|casino|castle|'
            r'casual|cat|catalog|catch|category|cattle|caught|cause|caution|cave|ceiling|'
            r'celery|cement|census|century|cereal|certain|chair|chalk|champion|change|chaos|'
            r'chapter|charge|chase|chat|cheap|check|cheese|chef|cherry|chest|chicken|chief|'
            r'child|chimney|choice|choose|chronic|chuckle|chunk|churn|cigar|cinnamon|circle|'
            r'citizen|city|civil|claim|clamp|clarify|clash|claw|clay|clean|clerk|clever|click|'
            r'client|cliff|climb|clinic|clip|clock|clog|close|cloth|cloud|clown|club|clump|'
            r'cluster|clutch|coach|coast|coconut|code|coffee|coil|coin|collect|color|column|'
            r'combine|come|comfort|comic|common|company|concert|conduct|confirm|congress|'
            r'connect|consider|control|convince|cook|cool|copper|copy|coral|core|corn|correct|'
            r'cost|cotton|couch|country|couple|course|cousin|cover|coyote|crack|cradle|craft|'
            r'cram|crane|crash|crater|crawl|crazy|cream|credit|creek|crew|cricket|crime|crisp|'
            r'critic|crop|cross|crouch|crowd|crucial|cruel|cruise|crumble|crunch|crush|cry|'
            r'crystal|cube|culture|cup|cupboard|curious|current|curtain|curve|cushion|custom|'
            r'cute|cycle|dad|damage|damp|dance|danger|daring|dash|daughter|dawn|day|deal|'
            r'debate|debris|decade|december|decide|decline|decorate|decrease|deer|defense|'
            r'define|defy|degree|delay|deliver|demand|demise|denial|dentist|deny|depart|depend|'
            r'deposit|depth|deputy|derive|describe|desert|design|desk|despair|destroy|detail|'
            r'detect|device|devote|diagram|dial|diamond|diary|dice|diesel|diet|differ|digital|'
            r'dignity|dilemma|dinner|dinosaur|direct|dirt|disagree|discover|disease|dish|'
            r'dismiss|disorder|display|distance|divert|divide|divorce|dizzy|doctor|document|'
            r'dog|doll|dolphin|domain|donate|donkey|donor|door|dose|double|dove|draft|dragon|'
            r'drama|drape|draw|dream|dress|drift|drill|drink|drip|drive|drop|drum|dry|duck|'
            r'dumb|dune|during|dust|dutch|duty|dwarf|dynamic|eager|eagle|early|earn|earth|'
            r'easily|east|easy|echo|ecology|economy|edge|edit|educate|effort|egg|eight|either|'
            r'elbow|elder|electric|elegant|element|elephant|elevator|elite|else|embark|embody|'
            r'embrace|emerge|emotion|employ|empower|empty|enable|enact|end|endless|endorse|'
            r'enemy|energy|enforce|engage|engine|enhance|enjoy|enlist|enough|enrich|enroll|'
            r'ensure|enter|entire|entry|envelope|episode|equal|equip|era|erase|erode|erosion|'
            r'error|erupt|escape|essay|essence|estate|eternal|ethics|evidence|evil|evoke|'
            r'evolve|exact|example|excess|exchange|excite|exclude|excuse|execute|exercise|'
            r'exhaust|exhibit|exile|exist|exit|exotic|expand|expect|expire|explain|expose|'
            r'express|extend|extra|eye|eyebrow|fabric|face|faculty|fade|faint|faith|fall|'
            r'false|fame|family|famous|fan|fancy|fantasy|farm|fashion|fat|fatal|father|'
            r'fatigue|fault|favorite|feature|february|federal|fee|feed|feel|female|fence|'
            r'festival|fetch|fever|few|fiber|fiction|field|figure|file|fill|film|filter|'
            r'final|find|fine|finger|finish|fire|firm|first|fiscal|fish|fit|fitness|fix|'
            r'flag|flame|flat|flavor|flee|flight|flip|float|flock|floor|flower|fluid|flush|'
            r'fly|foam|focus|fog|foil|fold|follow|food|foot|force|forest|forget|fork|fortune|'
            r'forum|forward|fossil|foster|found|fox|frame|frequent|fresh|friend|fringe|frog|'
            r'front|frost|frown|frozen|fruit|fuel|fun|funny|furnace|fury|future|gadget|gain|'
            r'galaxy|gallery|game|gap|garage|garbage|garden|garlic|garment|gas|gasp|gate|'
            r'gather|gauge|gaze|general|genius|genre|gentle|genuine|gesture|ghost|giant|gift|'
            r'giggle|ginger|giraffe|girl|give|glad|glance|glare|glass|glide|glimpse|globe|'
            r'gloom|glory|glove|glow|glue|goat|goddess|gold|good|goose|gorilla|gospel|gossip|'
            r'govern|gown|grab|grace|grain|grant|grape|grass|gravity|great|green|grid|grief|'
            r'grit|grocery|group|grow|grunt|guard|guess|guide|guilt|guitar|gun|gym|habit|'
            r'hair|half|hammer|hamster|hand|happy|harbor|hard|harsh|harvest|hat|have|hawk|'
            r'hazard|head|healthy|hear|heart|heavy|hedgehog|height|held|hello|helmet|help|'
            r'hen|hero|hidden|high|hill|hint|hip|hire|history|hobby|hockey|hold|hole|holiday|'
            r'hollow|home|honey|hood|hope|horn|horror|horse|hospital|host|hotel|hour|hover|'
            r'hub|huge|human|humble|humor|hundred|hungry|hunt|hurdle|hurry|hurt|husband|'
            r'hybrid|ice|icon|idea|identify|idle|ignore|ill|illegal|illness|image|imitate|'
            r'immense|immune|impact|impose|improve|impulse|inch|include|income|increase|index|'
            r'indicate|indoor|industry|infant|inflict|inform|inhale|inherit|initial|inject|'
            r'injury|inmate|inner|innocent|input|inquiry|insane|insect|inside|inspire|install|'
            r'intact|interest|into|invest|invite|involve|iron|island|isolate|issue|item|ivory|'
            r'jacket|jaguar|jar|jazz|jealous|jeans|jelly|jewel|job|join|joke|journey|joy|'
            r'judge|juice|jump|jungle|junior|junk|just|kangaroo|keen|keep|ketchup|key|kick|'
            r'kid|kidney|kind|kingdom|kiss|kit|kitchen|kite|kitten|kiwi|knee|knife|knock|'
            r'know|lab|label|labor|ladder|lady|lake|lamp|language|laptop|large|later|latin|'
            r'laugh|laundry|lava|law|lawn|lawsuit|layer|lazy|leader|leaf|learn|leave|lecture|'
            r'left|leg|legal|legend|leisure|lemon|lend|length|lens|leopard|lesson|letter|'
            r'level|liar|liberty|library|license|life|lift|light|like|limb|limit|link|lion|'
            r'liquid|list|little|live|lizard|load|loan|lobster|local|lock|logic|lonely|long|'
            r'loop|lottery|loud|lounge|love|loyal|lucky|luggage|lumber|lunar|lunch|luxury|'
            r'lying|machine|mad|magic|magnet|maid|mail|main|major|make|mammal|man|manage|'
            r'mandate|mango|mansion|manual|maple|marble|march|margin|marine|market|marriage|'
            r'mask|mass|master|match|material|math|matrix|matter|maximum|maze|meadow|mean|'
            r'measure|meat|mechanic|medal|media|melody|melt|member|memory|mention|menu|mercy|'
            r'merge|merit|merry|mesh|message|metal|method|middle|midnight|milk|million|mimic|'
            r'mind|minimum|minor|minute|miracle|mirror|misery|miss|mistake|mix|mixed|mixture|'
            r'mobile|model|modify|mom|moment|monitor|monkey|monster|month|moon|moral|more|'
            r'morning|mosquito|mother|motion|motor|mountain|mouse|move|movie|much|muffin|'
            r'mule|multiply|muscle|museum|mushroom|music|must|mutual|myself|mystery|myth|'
            r'naive|name|napkin|narrow|nasty|nation|nature|near|neck|need|needle|neglect|'
            r'neighbor|neither|nephew|nerve|nest|net|network|neutral|never|news|next|nice|'
            r'night|noble|noise|nominee|noodle|normal|north|nose|notable|note|nothing|notice|'
            r'novel|now|nuclear|number|nurse|nut|oak|obey|object|oblige|obscure|observe|'
            r'obtain|obvious|occur|ocean|october|odor|off|offer|office|often|oil|okay|old|'
            r'olive|olympic|omit|once|one|onion|online|only|open|opera|opinion|oppose|option|'
            r'orange|orbit|orchard|order|ordinary|organ|orient|original|orphan|ostrich|other|'
            r'outdoor|outer|output|outside|oval|oven|over|own|owner|oxygen|oyster|ozone|pact|'
            r'paddle|page|pair|palace|pale|palm|panda|panel|panic|panther|paper|parade|'
            r'parent|park|parrot|part|party|pass|patch|path|patient|patrol|pattern|pause|'
            r'pave|payment|peace|peanut|pear|peasant|pelican|pen|penalty|pencil|people|'
            r'pepper|perfect|permit|person|pet|phone|photo|phrase|physical|piano|picnic|'
            r'picture|piece|pig|pigeon|pill|pilot|pink|pioneer|pipe|pistol|pitch|pizza|'
            r'place|planet|plastic|plate|play|please|pledge|pluck|plug|plunge|poem|poet|'
            r'point|polar|pole|police|pond|pony|pool|popular|portion|position|possible|post|'
            r'potato|pottery|poverty|powder|power|practice|praise|predict|prefer|prepare|'
            r'present|pretty|prevent|price|pride|primary|print|priority|prison|private|'
            r'prize|problem|process|produce|profit|program|project|promote|proof|property|'
            r'prosper|protect|proud|provide|public|pudding|pull|pulp|pulse|pumpkin|punch|'
            r'pupil|puppy|purchase|purity|purpose|purse|push|put|puzzle|pyramid|quality|'
            r'quantum|quarter|question|quick|quiet|quilt|quit|quiz|quote|rabbit|raccoon|race|'
            r'rack|radar|radio|rail|rain|raise|rally|ramp|ranch|random|range|rapid|rare|'
            r'rate|rather|raven|raw|razor|ready|real|reason|rebel|rebuild|recall|receive|'
            r'recipe|record|recycle|reduce|reflect|reform|refuse|region|regret|regular|'
            r'reject|relax|release|relief|rely|remain|remember|remind|remove|render|renew|'
            r'rent|reopen|repair|repeat|replace|report|require|rescue|resemble|resist|'
            r'resource|response|result|retire|retreat|return|reunion|reveal|review|reward|'
            r'rhythm|rib|ribbon|rice|rich|ride|ridge|rifle|right|rigid|ring|riot|ripple|'
            r'rise|risk|ritual|rival|river|road|roast|rob|robust|rocket|romance|roof|rookie|'
            r'room|rose|rotate|rough|round|route|royal|rubber|rude|rug|rule|run|runway|rural|'
            r'sad|saddle|sadness|safe|sail|salad|salmon|salon|salt|salute|same|sample|sand|'
            r'satisfy|satoshi|sauce|sausage|save|say|scale|scan|scare|scatter|scene|scheme|'
            r'school|science|scissors|scorpion|scout|scrap|screen|script|scrub|sea|search|'
            r'season|seat|second|secret|section|security|seed|seek|segment|select|sell|'
            r'seminar|senior|sense|sentence|series|service|session|settle|setup|seven|shadow|'
            r'shaft|shallow|share|shed|shell|sheriff|shield|shift|shine|ship|shirt|shock|'
            r'shoe|shoot|shop|short|shoulder|shove|shrimp|shrug|shuffle|shy|sibling|sick|'
            r'side|siege|sight|sign|silent|silk|silly|silver|similar|simple|since|sing|'
            r'siren|sister|situate|six|size|skate|sketch|ski|skill|skin|skirt|skull|slab|'
            r'slam|sleep|slender|slice|slide|slight|slim|slogan|slot|slow|slush|small|smart|'
            r'smile|smoke|smooth|snack|snake|snap|sniff|snow|soap|soccer|social|sock|soda|'
            r'soft|solar|sold|soldier|solid|solution|solve|someone|song|soon|sorry|sort|'
            r'soul|sound|soup|source|south|space|spare|spatial|spawn|speak|special|speed|'
            r'spell|spend|sphere|spice|spider|spike|spin|spirit|split|spoil|sponsor|spoon|'
            r'sport|spot|spray|spread|spring|spy|square|squeeze|squirrel|stable|stadium|'
            r'staff|stage|stairs|stamp|stand|start|state|stay|steak|steel|stem|step|stereo|'
            r'stick|still|sting|stock|stomach|stone|stool|story|stove|strategy|street|'
            r'strike|strong|struggle|student|stuff|stumble|style|subject|submit|subway|'
            r'success|such|sudden|suffer|sugar|suggest|suit|summer|sun|sunny|sunset|super|'
            r'supply|supreme|sure|surface|surge|surprise|surround|survey|suspect|sustain|'
            r'swallow|swamp|swap|swear|sweet|swift|swim|swing|switch|sword|symbol|symptom|'
            r'syrup|system|table|tackle|tag|tail|talent|talk|tank|tape|target|task|taste|'
            r'tattoo|taxi|teach|team|tell|ten|tenant|tennis|tent|term|test|text|thank|that|'
            r'theme|then|theory|there|they|thing|this|thought|three|thrive|throw|thumb|'
            r'thunder|ticket|tide|tiger|tilt|timber|time|tiny|tip|tired|tissue|title|toast|'
            r'tobacco|today|toddler|toe|together|toilet|token|tomato|tomorrow|tone|tongue|'
            r'tonight|tool|tooth|top|topic|topple|torch|tornado|tortoise|toss|total|tourist|'
            r'toward|tower|town|toy|track|trade|traffic|tragic|train|transfer|trap|trash|'
            r'travel|tray|treat|tree|trend|trial|tribe|trick|trigger|trim|trip|trophy|'
            r'trouble|truck|true|truly|trumpet|trust|truth|try|tube|tuition|tumble|tuna|'
            r'tunnel|turkey|turn|turtle|twelve|twenty|twice|twin|twist|two|type|typical|'
            r'ugly|umbrella|unable|unaware|uncle|uncover|under|undo|unfair|unfold|unhappy|'
            r'uniform|unique|unit|universe|unknown|unlock|until|unusual|unveil|update|'
            r'upgrade|uphold|upon|upper|upset|urban|urge|usage|use|used|useful|useless|'
            r'usual|utility|vacant|vacuum|vague|valid|valley|valve|van|vanish|vapor|various|'
            r'vast|vault|vehicle|velvet|vendor|venture|venue|verb|verify|version|very|vessel|'
            r'veteran|viable|vicious|victory|video|view|village|vintage|violin|virtual|virus|'
            r'visa|visit|visual|vital|vivid|vocal|voice|void|volcano|volume|vote|voyage|wage|'
            r'wagon|wait|walk|wall|walnut|want|warfare|warm|warrior|wash|wasp|waste|water|'
            r'wave|way|wealth|weapon|wear|weasel|weather|web|wedding|weekend|weird|welcome|'
            r'west|wet|what|wheat|wheel|when|where|whip|whisper|wide|width|wife|wild|will|'
            r'win|window|wine|wing|wink|winner|winter|wire|wisdom|wise|wish|witness|wolf|'
            r'woman|wonder|wood|wool|word|work|world|worry|worth|wrap|wreck|wrestle|wrist|'
            r'write|wrong|yard|year|yellow|you|young|youth|zebra|zero|zone|zoo)\b',
            re.I
        )

        # Cryptocurrency exchange patterns
        self.exchange_deposit = re.compile(r'deposit.*(?:address|wallet)', re.I)
        self.exchange_withdraw = re.compile(r'withdraw.*(?:address|wallet)', re.I)

        # Mining pool patterns
        self.mining_pool = re.compile(r'(?:pool|mining).*(?:address|worker)', re.I)

        # ICO/Token patterns
        self.token_contract = re.compile(r'contract.*(?:address|token)', re.I)

    def _load_known_addresses(self):
        """Load database of known cryptocurrency addresses for enhanced detection"""
        # This would typically load from a database or file
        # For now, we'll use some well-known addresses as examples
        self.known_addresses = {
            # Bitcoin
            '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa': {'type': 'bitcoin', 'name': 'Genesis Block'},
            '3FupZp8UjobvkS1PQv8VTQL8f6ZeW8gZvK': {'type': 'bitcoin', 'name': 'FBI Silk Road Seizure'},

            # Ethereum
            '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed': {'type': 'ethereum', 'name': 'Test Address'},
            '0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe': {'type': 'ethereum', 'name': 'Test Address'},
        }

    def _load_crypto_keywords(self):
        """Load cryptocurrency-related keywords"""
        self.crypto_keywords = {
            'currencies': [
                'bitcoin', 'btc', 'ethereum', 'eth', 'litecoin', 'ltc', 'dogecoin', 'doge',
                'monero', 'xmr', 'zcash', 'zec', 'ripple', 'xrp', 'cardano', 'ada',
                'polkadot', 'dot', 'chainlink', 'link', 'stellar', 'xlm', 'tether', 'usdt',
                'usd-coin', 'usdc', 'binance-coin', 'bnb', 'solana', 'sol', 'avalanche', 'avax'
            ],
            'wallet_terms': [
                'wallet', 'address', 'private-key', 'public-key', 'mnemonic', 'seed',
                'passphrase', 'keystore', 'cold-storage', 'hot-wallet', 'hardware-wallet',
                'paper-wallet', 'brain-wallet', 'deterministic-wallet', 'hd-wallet'
            ],
            'exchange_terms': [
                'exchange', 'trading', 'coinbase', 'binance', 'kraken', 'bitfinex',
                'bitstamp', 'gemini', 'huobi', 'okex', 'kucoin', 'gate.io'
            ],
            'mining_terms': [
                'mining', 'miner', 'hashrate', 'difficulty', 'pool', 'asic', 'gpu-mining',
                'proof-of-work', 'pow', 'proof-of-stake', 'pos', 'staking', 'validator'
            ],
            'defi_terms': [
                'defi', 'decentralized-finance', 'uniswap', 'compound', 'aave', 'makerdao',
                'liquidity-pool', 'yield-farming', 'staking', 'governance-token'
            ],
            'security_terms': [
                'multisig', 'cold-storage', 'hardware-wallet', 'air-gapped', '2fa',
                'backup', 'recovery-phrase', 'seed-phrase', 'private-key-export'
            ]
        }

    def analyze_content(self, content: str) -> Dict[str, Any]:
        """Comprehensive crypto analysis of text content"""
        results = {
            'has_crypto_content': False,
            'confidence_score': 0.0,
            'patterns_found': [],
            'crypto_categories': {
                'wallets': [],
                'keys': [],
                'certificates': [],
                'hashes': [],
                'addresses': [],
                'signatures': [],
                'mnemonic_phrases': [],
                'exchange_references': [],
                'mining_references': []
            },
            'analysis_metadata': {
                'content_length': len(content),
                'patterns_checked': 0,
                'matches_found': 0
            }
        }

        if not content:
            return results

        # Track confidence factors
        confidence_factors = []

        # Analyze wallet addresses
        wallet_results = self._analyze_wallet_addresses(content)
        if wallet_results['addresses']:
            results['crypto_categories']['wallets'] = wallet_results['addresses']
            results['patterns_found'].extend(wallet_results['patterns'])
            confidence_factors.append(wallet_results['confidence'])

        # Analyze private keys
        key_results = self._analyze_private_keys(content)
        if key_results['keys']:
            results['crypto_categories']['keys'] = key_results['keys']
            results['patterns_found'].extend(key_results['patterns'])
            confidence_factors.append(key_results['confidence'])

        # Analyze certificates and PEM blocks
        cert_results = self._analyze_certificates(content)
        if cert_results['certificates']:
            results['crypto_categories']['certificates'] = cert_results['certificates']
            results['patterns_found'].extend(cert_results['patterns'])
            confidence_factors.append(cert_results['confidence'])

        # Analyze hashes
        hash_results = self._analyze_hashes(content)
        if hash_results['hashes']:
            results['crypto_categories']['hashes'] = hash_results['hashes']
            results['patterns_found'].extend(hash_results['patterns'])
            confidence_factors.append(hash_results['confidence'])

        # Analyze mnemonic phrases
        mnemonic_results = self._analyze_mnemonic_phrases(content)
        if mnemonic_results['phrases']:
            results['crypto_categories']['mnemonic_phrases'] = mnemonic_results['phrases']
            results['patterns_found'].extend(mnemonic_results['patterns'])
            confidence_factors.append(mnemonic_results['confidence'])

        # Analyze cryptocurrency keywords
        keyword_results = self._analyze_crypto_keywords(content)
        if keyword_results['keywords']:
            results['crypto_categories']['exchange_references'] = keyword_results.get('exchange_terms', [])
            results['crypto_categories']['mining_references'] = keyword_results.get('mining_terms', [])
            results['patterns_found'].extend(keyword_results['patterns'])
            confidence_factors.append(keyword_results['confidence'])

        # Calculate overall confidence
        if confidence_factors:
            results['confidence_score'] = min(sum(confidence_factors) / len(confidence_factors), 1.0)
            results['has_crypto_content'] = results['confidence_score'] > 0.3

        # Update metadata
        results['analysis_metadata']['patterns_checked'] = len(self.__dict__)
        results['analysis_metadata']['matches_found'] = len(results['patterns_found'])

        return results

    def quick_scan(self, content: str) -> Dict[str, Any]:
        """Quick crypto content scan for performance"""
        if not content:
            return {'has_crypto_content': False, 'confidence_score': 0.0}

        # Quick checks for obvious crypto content
        crypto_indicators = 0

        # Check for Bitcoin addresses
        if self.bitcoin_legacy.search(content) or self.bitcoin_segwit.search(content):
            crypto_indicators += 3

        # Check for Ethereum addresses
        if self.ethereum_address.search(content):
            crypto_indicators += 3

        # Check for private keys
        if self.private_key_hex.search(content) or self.private_key_wif.search(content):
            crypto_indicators += 4

        # Check for PEM blocks
        if self.pem_begin.search(content):
            crypto_indicators += 2

        # Check for crypto keywords
        content_lower = content.lower()
        for currency in self.crypto_keywords['currencies'][:10]:  # Check top 10
            if currency in content_lower:
                crypto_indicators += 1
                break

        confidence = min(crypto_indicators / 10.0, 1.0)

        return {
            'has_crypto_content': confidence > 0.3,
            'confidence_score': confidence,
            'indicators_found': crypto_indicators
        }

    def _analyze_wallet_addresses(self, content: str) -> Dict[str, Any]:
        """Analyze cryptocurrency wallet addresses"""
        results = {
            'addresses': [],
            'patterns': [],
            'confidence': 0.0
        }

        address_patterns = [
            ('Bitcoin Legacy', self.bitcoin_legacy),
            ('Bitcoin SegWit', self.bitcoin_segwit),
            ('Ethereum', self.ethereum_address),
            ('Litecoin', self.litecoin_address),
            ('Dogecoin', self.dogecoin_address),
            ('Monero', self.monero_address),
            ('Zcash', self.zcash_address),
            ('Ripple', self.ripple_address)
        ]

        for pattern_name, pattern in address_patterns:
            matches = pattern.findall(content)
            if matches:
                for match in matches:
                    # Validate address format
                    if self._validate_address_format(match, pattern_name.lower()):
                        results['addresses'].append({
                            'address': match,
                            'type': pattern_name.lower().replace(' ', '_'),
                            'currency': pattern_name.split()[0].lower(),
                            'validated': True
                        })

                results['patterns'].append({
                    'pattern_name': f'{pattern_name} Address',
                    'pattern_type': 'wallet_address',
                    'match_count': len(matches),
                    'matches': matches[:10],  # Limit stored matches
                    'confidence': 0.9
                })

        if results['addresses']:
            results['confidence'] = 0.8 + (len(results['addresses']) * 0.05)

        return results

    def _analyze_private_keys(self, content: str) -> Dict[str, Any]:
        """Analyze private keys and sensitive cryptographic material"""
        results = {
            'keys': [],
            'patterns': [],
            'confidence': 0.0
        }

        # Hex private keys
        hex_keys = self.private_key_hex.findall(content)
        if hex_keys:
            for key in hex_keys:
                if self._validate_private_key_hex(key):
                    results['keys'].append({
                        'key_type': 'hex_private_key',
                        'key_preview': key[:16] + '...' + key[-16:],
                        'length': len(key),
                        'format': 'hex'
                    })

            results['patterns'].append({
                'pattern_name': 'Hex Private Key',
                'pattern_type': 'private_key',
                'match_count': len(hex_keys),
                'confidence': 0.95
            })

        # WIF private keys
        wif_keys = self.private_key_wif.findall(content)
        if wif_keys:
            for key in wif_keys:
                results['keys'].append({
                    'key_type': 'wif_private_key',
                    'key_preview': key[:8] + '...' + key[-8:],
                    'length': len(key),
                    'format': 'wif'
                })

            results['patterns'].append({
                'pattern_name': 'WIF Private Key',
                'pattern_type': 'private_key',
                'match_count': len(wif_keys),
                'confidence': 0.95
            })

        # SSH keys
        ssh_keys = self.ssh_key.findall(content)
        if ssh_keys:
            results['patterns'].append({
                'pattern_name': 'SSH Key',
                'pattern_type': 'ssh_key',
                'match_count': len(ssh_keys),
                'confidence': 0.9
            })

        if results['keys']:
            results['confidence'] = 0.9

        return results

    def _analyze_certificates(self, content: str) -> Dict[str, Any]:
        """Analyze certificates and PEM blocks"""
        results = {
            'certificates': [],
            'patterns': [],
            'confidence': 0.0
        }

        # PEM blocks
        pem_blocks = self.pgp_block.findall(content)
        if pem_blocks:
            results['patterns'].append({
                'pattern_name': 'PGP Block',
                'pattern_type': 'certificate',
                'match_count': len(pem_blocks),
                'confidence': 0.85
            })
            results['confidence'] = 0.7

        # PEM headers/footers
        pem_begins = self.pem_begin.findall(content)
        pem_ends = self.pem_end.findall(content)

        if pem_begins or pem_ends:
            results['patterns'].append({
                'pattern_name': 'PEM Certificate',
                'pattern_type': 'certificate',
                'match_count': max(len(pem_begins), len(pem_ends)),
                'confidence': 0.8
            })
            results['confidence'] = max(results['confidence'], 0.6)

        return results

    def _analyze_hashes(self, content: str) -> Dict[str, Any]:
        """Analyze cryptographic hashes"""
        results = {
            'hashes': [],
            'patterns': [],
            'confidence': 0.0
        }

        hash_patterns = [
            ('MD5', self.md5_hash, 32),
            ('SHA1', self.sha1_hash, 40),
            ('SHA256', self.sha256_hash, 64),
            ('SHA512', self.sha512_hash, 128)
        ]

        for hash_name, pattern, expected_length in hash_patterns:
            matches = pattern.findall(content)
            if matches:
                valid_hashes = [h for h in matches if len(h) == expected_length]
                if valid_hashes:
                    results['hashes'].extend([{
                        'hash_type': hash_name.lower(),
                        'hash_value': h,
                        'length': len(h)
                    } for h in valid_hashes])

                    results['patterns'].append({
                        'pattern_name': f'{hash_name} Hash',
                        'pattern_type': 'hash',
                        'match_count': len(valid_hashes),
                        'confidence': 0.7
                    })

        if results['hashes']:
            results['confidence'] = 0.5 + (len(results['hashes']) * 0.1)

        return results

    def _analyze_mnemonic_phrases(self, content: str) -> Dict[str, Any]:
        """Analyze BIP39 mnemonic seed phrases"""
        results = {
            'phrases': [],
            'patterns': [],
            'confidence': 0.0
        }

        # Look for sequences of mnemonic words
        words = content.lower().split()
        mnemonic_words = []

        for word in words:
            if self.mnemonic_pattern.match(word):
                mnemonic_words.append(word)

        # Check for sequences (12, 15, 18, 21, 24 words are valid)
        if len(mnemonic_words) >= 12:
            # Simple heuristic: if we have 12+ mnemonic words, it might be a seed phrase
            valid_lengths = [12, 15, 18, 21, 24]
            for length in valid_lengths:
                if len(mnemonic_words) >= length:
                    phrase_candidate = ' '.join(mnemonic_words[:length])
                    results['phrases'].append({
                        'phrase_length': length,
                        'phrase_preview': ' '.join(mnemonic_words[:3]) + '...',
                        'word_count': length
                    })

            results['patterns'].append({
                'pattern_name': 'BIP39 Mnemonic Phrase',
                'pattern_type': 'mnemonic',
                'match_count': 1,
                'confidence': 0.8 if len(mnemonic_words) in valid_lengths else 0.6
            })

            results['confidence'] = 0.8 if len(mnemonic_words) in valid_lengths else 0.6

        return results

    def _analyze_crypto_keywords(self, content: str) -> Dict[str, Any]:
        """Analyze cryptocurrency-related keywords"""
        results = {
            'keywords': [],
            'patterns': [],
            'confidence': 0.0,
            'exchange_terms': [],
            'mining_terms': []
        }

        content_lower = content.lower()
        keyword_matches = 0

        # Check each category
        for category, keywords in self.crypto_keywords.items():
            category_matches = []
            for keyword in keywords:
                if keyword in content_lower:
                    category_matches.append(keyword)
                    keyword_matches += 1

            if category_matches:
                results[f'{category}'] = category_matches
                results['patterns'].append({
                    'pattern_name': f'Cryptocurrency {category.title()}',
                    'pattern_type': 'keyword',
                    'match_count': len(category_matches),
                    'matches': category_matches[:5],  # Limit stored matches
                    'confidence': 0.4 + (len(category_matches) * 0.1)
                })

        if keyword_matches > 0:
            results['confidence'] = min(0.3 + (keyword_matches * 0.05), 0.8)

        return results

    def analyze_wallet_address(self, address: str) -> Dict[str, Any]:
        """Analyze a specific wallet address"""
        result = {
            'valid': False,
            'cryptocurrency': 'unknown',
            'address_type': 'unknown',
            'network': 'unknown',
            'confidence': 0.0,
            'metadata': {}
        }

        if not address:
            return result

        # Bitcoin Legacy
        if self.bitcoin_legacy.match(address):
            if self._validate_bitcoin_address(address):
                result.update({
                    'valid': True,
                    'cryptocurrency': 'bitcoin',
                    'address_type': 'legacy',
                    'network': 'mainnet' if address[0] == '1' else 'testnet',
                    'confidence': 0.95
                })

        # Bitcoin SegWit
        elif self.bitcoin_segwit.match(address):
            result.update({
                'valid': True,
                'cryptocurrency': 'bitcoin',
                'address_type': 'segwit',
                'network': 'mainnet',
                'confidence': 0.95
            })

        # Ethereum
        elif self.ethereum_address.match(address):
            if self._validate_ethereum_address(address):
                result.update({
                    'valid': True,
                    'cryptocurrency': 'ethereum',
                    'address_type': 'standard',
                    'network': 'mainnet',
                    'confidence': 0.95
                })

        # Other cryptocurrencies...
        elif self.litecoin_address.match(address):
            result.update({
                'valid': True,
                'cryptocurrency': 'litecoin',
                'address_type': 'standard',
                'confidence': 0.9
            })

        # Check if it's a known address
        if address in self.known_addresses:
            info = self.known_addresses[address]
            result['metadata'].update({
                'known_address': True,
                'description': info.get('name', 'Known address')
            })
            result['confidence'] = min(result['confidence'] + 0.05, 1.0)

        return result

    def _validate_address_format(self, address: str, address_type: str) -> bool:
        """Validate address format using basic checks"""
        try:
            if address_type.startswith('bitcoin'):
                return self._validate_bitcoin_address(address)
            elif address_type == 'ethereum':
                return self._validate_ethereum_address(address)
            else:
                return True  # Basic validation passed for other types
        except Exception:
            return False

    def _validate_bitcoin_address(self, address: str) -> bool:
        """Validate Bitcoin address using Base58 checksum"""
        try:
            # This is a simplified validation
            # In production, you'd use a proper Base58 decoder
            if len(address) < 25 or len(address) > 34:
                return False

            # Check first character
            if address[0] not in '13':
                return False

            return True
        except Exception:
            return False

    def _validate_ethereum_address(self, address: str) -> bool:
        """Validate Ethereum address format"""
        try:
            # Remove 0x prefix
            if address.startswith('0x'):
                address = address[2:]

            # Check length
            if len(address) != 40:
                return False

            # Check if all characters are hex
            int(address, 16)
            return True
        except Exception:
            return False

    def _validate_private_key_hex(self, key: str) -> bool:
        """Validate hex private key"""
        try:
            # Check length (256 bits = 64 hex chars)
            if len(key) != 64:
                return False

            # Check if valid hex
            int(key, 16)

            # Check if in valid range (not zero, not >= order of secp256k1)
            key_int = int(key, 16)
            if key_int == 0:
                return False

            # secp256k1 order
            secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            if key_int >= secp256k1_order:
                return False

            return True
        except Exception:
            return False