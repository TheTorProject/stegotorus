/* Copyright 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "pgen.h"
#include "rng.h"
#include "base64.h"

#include <string>
#include <sstream>

using std::string;
using std::ostringstream;

// John Bauman's 1995 revision of the "General Service List" of common
// English words -- see http://jbauman.com/aboutgsl.html -- "a" and "I"
// removed.
const char *const words[] = {
  "the", "be", "of", "and", "to", "in", "he", "have", "it", "that",
  "for", "they", "with", "as", "not", "on", "she", "at", "by",
  "this", "we", "you", "do", "but", "from", "or", "which", "one",
  "would", "all", "will", "there", "say", "who", "make", "when", "can",
  "more", "if", "no", "man", "out", "other", "so", "what", "time", "up",
  "go", "about", "than", "into", "could", "state", "only", "new",
  "year", "some", "take", "come", "these", "know", "see", "use", "get",
  "like", "then", "first", "any", "work", "now", "may", "such", "give",
  "over", "think", "most", "even", "find", "day", "also", "after",
  "way", "many", "must", "look", "before", "great", "back", "through",
  "long", "where", "much", "should", "well", "people", "down", "own",
  "just", "because", "good", "each", "those", "feel", "seem", "how",
  "high", "too", "place", "little", "world", "very", "still", "nation",
  "hand", "old", "life", "tell", "write", "become", "here", "show",
  "house", "both", "between", "need", "mean", "call", "develop",
  "under", "last", "right", "move", "thing", "general", "school",
  "never", "same", "another", "begin", "while", "number", "part",
  "turn", "real", "leave", "might", "want", "point", "form", "off",
  "child", "few", "small", "since", "against", "ask", "late", "home",
  "interest", "large", "person", "end", "open", "public", "follow",
  "during", "present", "without", "again", "hold", "govern", "around",
  "possible", "head", "consider", "word", "program", "problem",
  "however", "lead", "system", "set", "order", "eye", "plan", "run",
  "keep", "face", "fact", "group", "play", "stand", "increase", "early",
  "course", "change", "help", "line", "city", "put", "close", "case",
  "force", "meet", "once", "water", "upon", "war", "build", "hear",
  "light", "unite", "live", "every", "country", "bring", "center",
  "let", "side", "try", "provide", "continue", "name", "certain",
  "power", "pay", "result", "question", "study", "woman", "member",
  "until", "far", "night", "always", "service", "away", "report",
  "something", "company", "week", "church", "toward", "start", "social",
  "room", "figure", "nature", "though", "young", "less", "enough",
  "almost", "read", "include", "president", "nothing", "yet", "better",
  "big", "boy", "cost", "business", "value", "second", "why", "clear",
  "expect", "family", "complete", "act", "sense", "mind", "experience",
  "art", "next", "near", "direct", "car", "law", "industry",
  "important", "girl", "god", "several", "matter", "usual", "rather",
  "per", "often", "kind", "among", "white", "reason", "action",
  "return", "foot", "care", "simple", "within", "love", "human",
  "along", "appear", "doctor", "believe", "speak", "active", "student",
  "month", "drive", "concern", "best", "door", "hope", "example",
  "inform", "body", "ever", "least", "probable", "understand", "reach",
  "effect", "different", "idea", "whole", "control", "condition",
  "field", "pass", "fall", "note", "special", "talk", "particular",
  "today", "measure", "walk", "teach", "low", "hour", "type", "carry",
  "rate", "remain", "full", "street", "easy", "although", "record",
  "sit", "determine", "level", "local", "sure", "receive", "thus",
  "moment", "spirit", "train", "college", "religion", "perhaps",
  "music", "grow", "free", "cause", "serve", "age", "book", "board",
  "recent", "sound", "office", "cut", "step", "class", "true",
  "history", "position", "above", "strong", "friend", "necessary",
  "add", "court", "deal", "tax", "support", "party", "whether",
  "either", "land", "material", "happen", "education", "death", "agree",
  "arm", "mother", "across", "quite", "anything", "town", "past",
  "view", "society", "manage", "answer", "break", "organize", "half",
  "fire", "lose", "money", "stop", "actual", "already", "effort",
  "wait", "department", "able", "political", "learn", "voice", "air",
  "together", "shall", "cover", "common", "subject", "draw", "short",
  "wife", "treat", "limit", "road", "letter", "color", "behind",
  "produce", "send", "term", "total", "university", "rise", "century",
  "success", "minute", "remember", "purpose", "test", "fight", "watch",
  "situation", "south", "ago", "difference", "stage", "father", "table",
  "rest", "bear", "entire", "market", "prepare", "explain", "offer",
  "plant", "charge", "ground", "west", "picture", "hard", "front",
  "lie", "modern", "dark", "surface", "rule", "regard", "dance",
  "peace", "observe", "future", "wall", "farm", "claim", "firm",
  "operation", "further", "pressure", "property", "morning", "amount",
  "top", "outside", "piece", "sometimes", "beauty", "trade", "fear",
  "demand", "wonder", "list", "accept", "judge", "paint", "mile",
  "soon", "responsible", "allow", "secretary", "heart", "union", "slow",
  "island", "enter", "drink", "story", "experiment", "stay", "paper",
  "space", "apply", "decide", "share", "desire", "spend", "sign",
  "therefore", "various", "visit", "supply", "officer", "doubt",
  "private", "immediate", "wish", "contain", "feed", "raise",
  "describe", "ready", "horse", "son", "exist", "north", "suggest",
  "station", "effective", "food", "deep", "wide", "alone", "character",
  "english", "happy", "critic", "unit", "product", "respect", "drop",
  "nor", "fill", "cold", "represent", "sudden", "basic", "kill", "fine",
  "trouble", "mark", "single", "press", "heavy", "attempt", "origin",
  "standard", "everything", "committee", "moral", "black", "red", "bad",
  "earth", "accord", "else", "mere", "die", "remark", "basis", "except",
  "equal", "east", "event", "employ", "defense", "smile", "river",
  "improve", "game", "detail", "account", "cent", "sort", "reduce",
  "club", "buy", "attention", "ship", "decision", "wear", "inside",
  "win", "suppose", "ride", "operate", "realize", "sale", "choose",
  "park", "square", "vote", "price", "district", "dead", "foreign",
  "window", "beyond", "direction", "strike", "instead", "trial",
  "practice", "catch", "opportunity", "likely", "recognize", "permit",
  "serious", "attack", "floor", "association", "spring", "lot", "stock",
  "lack", "hair", "science", "relation", "profession", "pattern",
  "quick", "medical", "influence", "occasion", "machine", "compare",
  "husband", "blue", "international", "fair", "especially", "indeed",
  "imagine", "surprise", "average", "official", "temperature",
  "difficult", "sing", "hit", "tree", "race", "police", "touch",
  "relative", "throw", "quality", "former", "pull", "chance", "prove",
  "argue", "settle", "growth", "date", "heat", "save", "performance",
  "count", "production", "listen", "main", "pick", "size", "cool",
  "army", "patient", "combine", "summer", "hall", "slight", "command",
  "enjoy", "length", "proper", "express", "health", "chief", "evening",
  "store", "language", "degree", "lay", "current", "gun", "dog",
  "hotel", "strange", "separate", "boat", "fail", "clean", "dress",
  "anyone", "gain", "pain", "object", "knowledge", "depend", "relate",
  "below", "dollar", "advance", "shape", "arrange", "population", "yes",
  "sell", "mention", "dry", "check", "poet", "sleep", "join", "hot",
  "bed", "electric", "dream", "due", "season", "manner", "fit", "left",
  "progress", "neither", "strength", "notice", "finish", "opinion",
  "bill", "western", "truth", "wrong", "travel", "suit", "bank",
  "exact", "honor", "brother", "quiet", "marry", "corner", "handle",
  "danger", "hospital", "pool", "promise", "blood", "shoot", "scene",
  "literature", "arrive", "film", "base", "freedom", "bar", "maybe",
  "hang", "suffer", "manufacture", "frequent", "rock", "loss", "burn",
  "sun", "audience", "essential", "glass", "prevent", "poem", "poor",
  "inch", "song", "skill", "post", "popular", "radio", "animal",
  "conscious", "worth", "eat", "election", "faith", "wave", "murder",
  "model", "forget", "extend", "edge", "distance", "memory",
  "recommend", "division", "staff", "leg", "discussion", "address",
  "fly", "dependent", "ball", "shake", "frame", "extreme", "engineer",
  "thick", "comfort", "latter", "camp", "oil", "discover", "examine",
  "difficulty", "tooth", "middle", "choice", "refer", "enemy",
  "practical", "marriage", "bridge", "declare", "lady", "cross",
  "daily", "afternoon", "attend", "director", "balance", "wash",
  "capital", "speed", "block", "citizen", "mouth", "hill", "green",
  "please", "motor", "agency", "encourage", "governor", "worry",
  "affair", "shoulder", "bright", "mass", "sample", "pretty", "repeat",
  "roll", "push", "trip", "council", "clothe", "parent", "forward",
  "sharp", "straight", "gas", "weight", "discuss", "fix", "load",
  "master", "whatever", "round", "rapid", "laugh", "finger", "spot",
  "propose", "shop", "broad", "replace", "reply", "extent", "lock",
  "employee", "ahead", "sight", "spread", "wind", "approve", "destroy",
  "none", "pound", "fame", "importance", "reflect", "advantage",
  "match", "regular", "wage", "refuse", "existence", "hardly",
  "perform", "title", "tend", "exercise", "thin", "coat", "bit",
  "mountain", "youth", "behavior", "newspaper", "secret", "ability",
  "sea", "soft", "justice", "reasonable", "circle", "solid", "page",
  "weapon", "fast", "representative", "search", "pure", "escape",
  "crowd", "stick", "telephone", "avoid", "garden", "favor", "news",
  "unless", "dinner", "someone", "signal", "yard", "ideal", "warm",
  "miss", "shelter", "soldier", "article", "cry", "captain", "familiar",
  "seat", "guest", "weak", "excite", "king", "everyone", "wine", "hole",
  "duty", "beat", "perfect", "bottom", "compose", "battle", "expense",
  "cattle", "flow", "kitchen", "dust", "bottle", "admit", "tear",
  "tire", "expression", "exception", "application", "belong", "rich",
  "failure", "struggle", "instrument", "variety", "narrow", "theater",
  "collection", "rain", "review", "preserve", "leadership", "clay",
  "daughter", "fellow", "swing", "thank", "library", "fat", "reserve",
  "tour", "nice", "warn", "ring", "bitter", "chair", "yesterday",
  "scientific", "flower", "wheel", "solution", "aim", "gather",
  "invite", "moreover", "fresh", "forest", "winter", "box", "belief",
  "ordinary", "impossible", "print", "gray", "taste", "lip", "speech",
  "reference", "stain", "connection", "otherwise", "stretch", "knife",
  "village", "blow", "mistake", "sweet", "shout", "divide", "guard",
  "worse", "exchange", "rare", "commercial", "request", "appoint",
  "agent", "dependence", "bird", "wild", "motion", "guess", "neighbor",
  "seed", "fashion", "loan", "correct", "plain", "mail", "retire",
  "opposite", "prefer", "safe", "evil", "double", "wood", "empty",
  "baby", "advise", "content", "sport", "lift", "literary", "curious",
  "tie", "flat", "message", "neck", "hate", "dirt", "delight", "trust",
  "nobody", "valley", "tool", "presence", "cook", "railroad",
  "minister", "coffee", "brush", "beside", "collect", "guide", "luck",
  "profit", "lord", "everybody", "prison", "cloud", "slave", "chairman",
  "soil", "distinguish", "introduce", "urge", "blind", "arise", "upper",
  "curve", "membership", "key", "entertain", "soul", "neighborhood",
  "friendly", "pair", "stone", "lean", "protect", "advertise",
  "mystery", "welcome", "knee", "jump", "snake", "stream", "avenue",
  "brown", "disease", "hat", "excellent", "formal", "snow", "sheet",
  "somehow", "unity", "sky", "rough", "smooth", "weather", "steady",
  "threaten", "depth", "oppose", "deliver", "ancient", "pray", "adopt",
  "birth", "appearance", "universe", "busy", "hurry", "coast", "forth",
  "smell", "furnish", "female", "hide", "wire", "proposal", "ought",
  "victory", "quarter", "engine", "customer", "waste", "fool", "intend",
  "intention", "desk", "politics", "passage", "lawyer", "root", "climb",
  "metal", "gradual", "hunt", "protection", "satisfy", "roof", "branch",
  "pleasure", "witness", "loose", "nose", "mine", "band", "aside",
  "risk", "tomorrow", "remind", "ear", "fish", "shore", "operator",
  "civilize", "being", "silent", "screen", "bind", "earn", "pack",
  "colony", "besides", "slip", "cousin", "scale", "relief", "explore",
  "stem", "brain", "musician", "defend", "bend", "somebody", "shadow",
  "mix", "smoke", "description", "fruit", "guilt", "yield", "sensitive",
  "salt", "pale", "sweep", "completion", "throat", "agriculture",
  "admire", "gentle", "dozen", "particle", "pleasant", "bay", "cup",
  "competition", "moon", "terrible", "strip", "mechanic", "shock",
  "conversation", "angle", "tall", "plenty", "star", "yellow", "sick",
  "thorough", "absolute", "succeed", "surround", "proud", "dear",
  "card", "lake", "breath", "afraid", "silence", "onto", "shoe",
  "somewhere", "chain", "slide", "copy", "machinery", "wake", "severe",
  "pocket", "bone", "honest", "freeze", "dictionary", "calm", "swim",
  "ice", "male", "skin", "crack", "rush", "wet", "meat", "commerce",
  "joint", "gift", "host", "suspect", "path", "uncle", "afford",
  "instant", "satisfactory", "height", "track", "confidence", "grass",
  "suggestion", "favorite", "breakfast", "apart", "chest", "entrance",
  "march", "sink", "northern", "iron", "alive", "ill", "bag", "disturb",
  "native", "bedroom", "violent", "beneath", "pause", "tough",
  "substance", "threat", "charm", "absence", "factory", "spite", "meal",
  "universal", "accident", "highway", "sentence", "liberty", "wise",
  "noise", "discovery", "tube", "flash", "twist", "fence", "childhood",
  "joy", "sister", "sad", "efficiency", "disappear", "defeat",
  "extensive", "rent", "comparison", "possess", "grace", "flesh",
  "liquid", "scientist", "ease", "heaven", "milk", "sympathy", "rank",
  "restaurant", "frequency", "angry", "shade", "accuse", "necessity",
  "knock", "loud", "permanent", "row", "lovely", "confuse", "gold",
  "frighten", "solve", "grave", "salary", "photograph", "advice",
  "abroad", "wound", "virtue", "dare", "queen", "extra", "attract",
  "numerous", "pink", "gate", "expensive", "shut", "chicken", "forgive",
  "holy", "wooden", "prompt", "crime", "sorry", "republic", "anger",
  "visitor", "pile", "violence", "steel", "wing", "stair", "partner",
  "delay", "gentleman", "pour", "confusion", "damage", "kick", "safety",
  "burst", "network", "resistance", "screw", "pride", "till", "hire",
  "verb", "preach", "clerk", "everywhere", "anyway", "fan", "connect",
  "egg", "efficient", "grain", "calculate", "drag", "opposition",
  "worship", "arrest", "discipline", "string", "harbor", "camera",
  "mechanism", "cow", "grand", "funny", "insurance", "reduction",
  "strict", "lesson", "tight", "sand", "plate", "qualify", "elsewhere",
  "mad", "interference", "pupil", "fold", "royal", "valuable",
  "whisper", "anybody", "hurt", "excess", "quantity", "fun", "mud",
  "extension", "recognition", "kiss", "crop", "sail", "attractive",
  "habit", "relieve", "wisdom", "persuade", "certainty", "cloth",
  "eager", "deserve", "sympathetic", "cure", "trap", "puzzle", "powder",
  "raw", "mankind", "glad", "blame", "whenever", "anxiety", "bus",
  "tremble", "sacred", "fortunate", "glory", "golden", "neat",
  "weekend", "treasury", "overcome", "cat", "sacrifice", "complain",
  "elect", "roar", "sake", "temple", "self", "compete", "nurse",
  "stuff", "stomach", "peculiar", "repair", "storm", "ton", "desert",
  "allowance", "servant", "hunger", "conscience", "bread", "crash",
  "tip", "strengthen", "proof", "generous", "sir", "tonight", "whip",
  "tongue", "mill", "merchant", "coal", "ruin", "introduction",
  "courage", "actor", "belt", "stir", "package", "punish", "reflection",
  "breathe", "anywhere", "amuse", "dull", "fate", "net", "fellowship",
  "fault", "furniture", "beam", "pencil", "border", "disappoint",
  "flame", "joke", "bless", "corn", "shell", "tempt", "supper",
  "destruction", "dive", "anxious", "shine", "cheap", "dish", "distant",
  "greet", "flood", "excuse", "insect", "ocean", "ceremony", "decrease",
  "prize", "harm", "insure", "verse", "pot", "sincere", "cotton",
  "leaf", "rub", "medicine", "stroke", "bite", "lung", "lonely",
  "admission", "stupid", "scratch", "composition", "broadcast", "drum",
  "resist", "neglect", "absent", "passenger", "adventure", "beg",
  "pipe", "beard", "bold", "meanwhile", "devil", "cheer", "nut",
  "split", "melt", "swear", "sugar", "bury", "wipe", "faint",
  "creature", "tail", "wealth", "earnest", "translate", "suspicion",
  "noble", "inquiry", "journey", "hesitate", "extraordinary", "borrow",
  "owe", "funeral", "ambition", "mixture", "slope", "criminal",
  "seldom", "map", "spin", "praise", "spare", "plow", "telegraph",
  "barrel", "straighten", "scarce", "lunch", "slavery", "creep",
  "sweat", "gay", "stiff", "brave", "seize", "convenient", "horizon",
  "moderate", "complicate", "dig", "curse", "weigh", "priest",
  "excessive", "quarrel", "widow", "modest", "dine", "politician",
  "custom", "educate", "salesman", "nail", "tap", "eastern",
  "possession", "satisfaction", "behave", "mercy", "scatter",
  "objection", "silver", "tent", "saddle", "wrap", "nest", "grind",
  "spell", "plaster", "arch", "swell", "friendship", "bath", "bundle",
  "grateful", "crown", "boundary", "nowhere", "asleep", "clock", "boil",
  "altogether", "lend", "holiday", "precious", "wander", "ugly",
  "reputation", "ticket", "pretend", "dismiss", "delicate", "despair",
  "awake", "tea", "false", "fortune", "cap", "thread", "haste", "bare",
  "shirt", "bargain", "leather", "rail", "butter", "dot", "inquire",
  "warmth", "decisive", "vessel", "pity", "steam", "pin", "bound",
  "companion", "toe", "reward", "forbid", "wherever", "tower", "bathe",
  "lodge", "swallow", "multiply", "bow", "kingdom", "garage",
  "permission", "pump", "prevention", "urgent", "aunt", "zero", "idle",
  "fever", "christmas", "regret", "jaw", "soap", "pronounce", "empire",
  "bowl", "outline", "organ", "imitation", "caution", "mineral",
  "disagree", "blade", "trick", "treasure", "immense", "convenience",
  "disapprove", "destructive", "fork", "noon", "ownership", "tune",
  "polish", "poison", "shame", "loyalty", "cottage", "astonish",
  "shave", "feather", "sauce", "lid", "debt", "fade", "confess",
  "classification", "descend", "cape", "mild", "clever", "envelope",
  "invention", "sheep", "splendid", "stamp", "float", "brick", "rice",
  "businessman", "backward", "qualification", "artificial",
  "attraction", "lamp", "curl", "shower", "elder", "bunch", "bell",
  "steer", "flavor", "spit", "rob", "cream", "interrupt", "pen",
  "weave", "orange", "rescue", "crush", "humble", "fancy", "decay",
  "polite", "tribe", "bleed", "coin", "fond", "autumn", "classify",
  "omit", "loyal", "needle", "lessen", "complaint", "pad", "steep",
  "skirt", "curtain", "calculation", "laughter", "solemn", "grease",
  "interfere", "explode", "fasten", "flag", "resign", "postpone",
  "patience", "boast", "rope", "envy", "airplane", "rid", "shield",
  "veil", "kneel", "tray", "explosive", "brass", "taxi", "wax", "duck",
  "button", "invent", "remedy", "bush", "thunder", "weaken", "poverty",
  "scrape", "arrow", "tender", "cruel", "soften", "mouse", "hay",
  "anyhow", "alike", "circular", "juice", "shelf", "bake", "hatred",
  "cautious", "basket", "wreck", "width", "confident", "log", "heap",
  "suck", "ladder", "gap", "obey", "hut", "axe", "translation",
  "collar", "delivery", "reproduce", "confession", "pan", "prejudice",
  "voyage", "tobacco", "simplicity", "paste", "cake", "elephant",
  "ribbon", "harvest", "ashamed", "cave", "customary", "thief", "damp",
  "sew", "rust", "separation", "waiter", "pet", "straw", "upset",
  "towel", "refresh", "essence", "fur", "ambitious", "defendant",
  "daylight", "dip", "suspicious", "imaginary", "ash", "carriage",
  "educator", "saw", "stove", "rubber", "rug", "misery", "awkward",
  "rival", "roast", "deed", "preference", "explosion", "theatrical",
  "cultivate", "collector", "miserable", "wrist", "rabbit", "accustom",
  "tide", "insult", "thumb", "lump", "annoy", "toy", "heal", "shallow",
  "repetition", "soup", "whistle", "scenery", "apple", "offense",
  "cork", "ripe", "temper", "sore", "pinch", "diamond", "razor",
  "imaginative", "hook", "copper", "landlord", "influential", "rot",
  "hollow", "enclose", "harden", "wicked", "stiffen", "silk", "upright",
  "selfish", "stripe", "pig", "inward", "excellence", "rake", "purple",
  "hasten", "shorten", "applause", "ache", "apology", "knot", "nephew",
  "cushion", "drown", "nursery", "pint", "fierce", "imitate", "aloud",
  "gaiety", "robbery", "tighten", "perfection", "scorn", "whoever",
  "trunk", "wool", "sailor", "competitor", "moonlight", "deer", "bean",
  "everyday", "drawer", "disregard", "nowadays", "patriotic", "tin",
  "penny", "cage", "pardon", "lately", "offend", "coarse", "spoil",
  "horizontal", "sting", "ditch", "librarian", "meantime", "cough",
  "deaf", "sword", "messenger", "vain", "castle", "elastic", "comb",
  "rod", "widen", "sorrow", "inventor", "cliff", "umbrella",
  "interruption", "merry", "gallon", "conquest", "headache", "tailor",
  "bucket", "scent", "signature", "cart", "darken", "sometime",
  "applaud", "underneath", "hello", "pretense", "descent", "conquer",
  "framework", "confidential", "adoption", "disgust", "waist",
  "momentary", "receipt", "pearl", "ray", "lazy", "limb", "grammatical",
  "beast", "monkey", "jewel", "persuasion", "obedience", "sock",
  "vowel", "hammer", "inn", "chimney", "dissatisfaction", "annoyance",
  "ornament", "honesty", "outward", "sharpen", "handkerchief", "greed",
  "heavenly", "thirst", "niece", "spill", "loaf", "wheat", "worm",
  "secrecy", "rude", "heighten", "flatten", "loosen", "cheese",
  "rivalry", "royalty", "discontent", "complication", "fright",
  "indoor", "flour", "actress", "congratulation", "ounce", "fry",
  "everlasting", "goat", "ink", "disappearance", "reproduction",
  "thicken", "avoidance", "spoon", "strap", "deceive", "lengthen",
  "revenge", "correction", "descendant", "hesitation", "spade", "basin",
  "weed", "omission", "old-fashioned", "bicycle", "breadth",
  "photography", "coward", "mat", "rejoice", "cheat", "congratulate",
  "discomfort", "enclosure", "attentive", "paw", "overflow",
  "dissatisfy", "multiplication", "whichever", "tidy", "bribe", "mend",
  "stocking", "feast", "nuisance", "thorn", "tame", "inclusive",
  "homemade", "handwriting", "chalk", "sour", "slippery", "procession",
  "ripen", "jealous", "jealousy", "liar", "homecoming", "barber",
  "whiten", "berry", "lighten", "pigeon", "hinder", "bravery",
  "baggage", "noun", "amongst", "grammar", "cultivation",
  "companionship", "rubbish", "modesty", "woolen", "deepen", "pastry",
  "cupboard", "quart", "canal", "notebook", "deceit", "parcel",
  "brighten", "moderation", "punctual", "hurrah", "lipstick",
  "uppermost", "fatten", "conqueror", "hindrance", "cowardice",
  "obedient", "saucer", "madden", "scold", "weekday", "rotten",
  "disrespect", "widower", "deafen", "donkey", "businesslike",
  "motherhood", "sadden", "handshake", "calculator", "headdress",
  "scissors", "translator", "possessor", "shilling", "redden",
  "motherly", "whose", "cultivator", "whom", "homework", "electrician",
  "oar", "bribery", "sweeten", "sow", "pronunciation", "beak", "plural",
};

const size_t nwords = (sizeof words) / (sizeof words[0]);

enum payload_type {
  PT_HTML,
  PT_JS,
  PT_SWF,
  PT_PDF
};

const char *const type_extensions[] = { ".html", ".js", ".swf", ".pdf" };
const char *const type_mimes[] = {
  "text/html; charset=utf-8",
  "text/javascript",
  "application/x-shockwave-flash",
  "application/pdf"
};

// payloads.cc uses the *file extension* on the URL to decide what to
// send back.  Use HTML half of the time, JS three-quarters of the
// remaining time, and PDF or SWF each half of what's left over.
static payload_type
pick_payload_type()
{
  uint8_t b;
  rng_bytes(&b, 1);
  if (b >= 128)
    return PT_HTML;
  else if (b >= 32)
    return PT_JS;
  else if (b >= 16)
    return PT_SWF;
  else
    return PT_PDF;
}

static void
gen_one_uripath(ostringstream& os)
{
  int n = rng_range_geom(10, 3);
  for (int i = 0; i < n; i++)
    os << words[rng_range_geom(nwords, nwords/3)] << '/';

  os << words[rng_range_geom(nwords, nwords/3)];
  os << type_extensions[pick_payload_type()];
}

static void
gen_one_hostname(ostringstream& os)
{
  unsigned int choices = rng_int(0x10);
  bool use_www  = choices & 0x01;
  bool use_subd = choices & 0x02;
  unsigned int tld = (choices & 0x0C) >> 2;

  const char *const tlds[4] = { ".com", ".org", ".sv", ".ac.uk" };

  if (use_www)
    os << "www.";
  if (use_subd)
    os << words[rng_range_geom(nwords, nwords/3)] << '.';

  os << words[rng_range_geom(nwords, nwords/3)] << tlds[tld];
}

static void
gen_one_cookie_header(ostringstream& os)
{
  int n = rng_range(1,5);
  uint8_t buf[80];
  char obuf[160];
  int m;
  ptrdiff_t mo;
  base64::encoder enc(false, '_', '.', '-');

  for (int i = 0; i < n; i++) {
    os << words[rng_range_geom(nwords, nwords/3)] << '=';

    m = rng_range_geom(80, 20);
    rng_bytes(buf, m);
    mo = enc.encode((const char *)buf, m, obuf);
    mo += enc.encode_end(obuf + mo);
    obuf[mo] = '\0';
    os << obuf;

    if (i+1 < n)
      os << ',';
  }
}

static void
gen_one_html(ostringstream& cs, size_t approx_size)
{
  // HTML needs to be substantially bigger than anything else,
  // since we can only use the scripts which are only a small part
  // of the file.
  approx_size *= 5;

  cs << "<!doctype html>\n<html><head>\n<title>";
  int n = rng_range_geom(6, 2);
  for (int i = 0; i < n; i++)
    cs << words[rng_int(nwords)] << ' ';
  cs << words[rng_int(nwords)]
     << "</title>\n</head><body>\n<p>";

  n = rng_range_geom(50, 20);
  bool in_script = false;
  do {
    cs << words[rng_int(nwords)] << ' ';
    n--;
    if (n <= 0) {
      n = rng_range_geom(50, 20);
      if (in_script) {
        cs << "</script>\n<p>";
        in_script = false;
      } else {
        // jsSteg insists on <script type="text/javascript"> for no
        // apparent reason (and this is as a fixed string, not as
        // properly parsed HTML).
        cs << "</p>\n<script type=\"text/javascript\">";
        in_script = true;
      }
    }
  } while (size_t(cs.tellp()) < approx_size);

  cs << (in_script ? "</script>" : "</p>") << "\n</body></html>\n";
}

static void
gen_one_js(ostringstream& cs, size_t approx_size)
{
  const char *const js_keywords[] = {
    "break", "case", "catch", "class", "continue", "debugger", "default",
    "delete", "do", "else", "enum", "export", "extends", "false",
    "finally", "for", "function", "if", "implements", "import", "in",
    "instanceof", "interface", "let", "new", "null", "package", "private",
    "protected", "public", "return", "static", "super", "switch", "this",
    "throw", "true", "try", "typeof", "var", "void", "while", "with", "yield",
  };
  const size_t n_js_keywords = (sizeof js_keywords) / (sizeof js_keywords[0]);

  const char *const js_punct[] = {
    "(", ")", "[", "]", "{", "}", ":", ";", ".", ",",
    "+", "-", "/", "*", "%", "++", "--", "&", "|", "<<", ">>", ">>>",
    "=", "*=", "/=", "%=", "+=", "-=", "<<=", ">>=", ">>>=", "&=", "^=", "|=",
    "==", "!=", "===", "!==", ">", ">=", "<", "<=", "&&", "||", "!"
  };
  const size_t n_js_punct = (sizeof js_punct) / (sizeof js_punct[0]);

  do {
    uint8_t which;
    rng_bytes(&which, 1);
    if (which < 32)
      cs << js_keywords[rng_int(n_js_keywords)];
    else
      cs << words[rng_range_geom(nwords, nwords/3)];

    rng_bytes(&which, 1);
    if (which < 128)
      cs << " ";
    else
      cs << js_punct[rng_int(n_js_punct)];

  } while (size_t(cs.tellp()) < approx_size);
}

static void
gen_one_swf(ostringstream& cs, size_t approx_size)
{
  // This does not attempt to produce the SWF file format *at all*,
  // only its magic number and length field.  swfSteg.cc is presently
  // very nearly as callous: it preserves the first 1508 and last 1500
  // bytes of the file, and makes the length field be accurate.
  uint32_t size = approx_size + 3008;

  cs << "CWS\t"; // compressed, version 9; it's not compressed now,
                 // but it will be after swfSteg.cc gets done with it
  cs << uint8_t((size & 0x000000ff)) // length is little endian
     << uint8_t((size & 0x0000ff00) >>  8)
     << uint8_t((size & 0x00ff0000) >> 16)
     << uint8_t((size & 0xff000000) >> 24);

  for (int i = 0; i < 1500; i++)
    cs << '\xEE';
  for (size_t i = 0; i < approx_size; i++)
    cs << '\xDD';
  for (int i = 0; i < 1500; i++)
    cs << '\xCC';
}

static void
gen_one_pdf(ostringstream& cs, size_t approx_size)
{
  // This only duplicates the part of the PDF format that pdfSteg.cc
  // actually looks for: in particular, we do not attempt to generate
  // a valid trailer.  (It wouldn't be terribly hard to add.)

  int ctr = 1;
  cs << "%PDF-1.5\n%\xA0\xA1\xA2\xA3\n";
  do {
    int size = rng_range_geom(2048, 512);

    cs << ctr << " 0 obj <</Length " << size << ">>\nstream\n";
    ctr++;

    for (int i = 0; i < size; i++)
      cs << '\xBB';

    cs << "\nendstream\nendobj\n";
  } while (size_t(cs.tellp()) < approx_size);

  cs << "%%EOF\n";
}

static void
gen_one_client_trace(ostringstream& os, pentry_header& pe)
{
  pe.ptype = htons(TYPE_HTTP_REQUEST);
  pe.port = htons(80);

  os << "GET /";

  gen_one_uripath(os);

  os << " HTTP/1.1\r\nHost: ";

  gen_one_hostname(os);

  os <<
    "\r\nUser-Agent: Mozilla/5.0 (Macintosh; "
        "Intel Mac OS X 10.6; rv:10.0) Gecko/20100101 Firefox/10.0"
    "\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    "\r\nAccept-Language: en-us,en;q=0.5"
    "\r\nAccept-Encoding: gzip, deflate"
    "\r\nCookie: ";

  gen_one_cookie_header(os);

  os << "\r\nConnection: keep-alive\r\n\r\n";
}

static void
gen_one_server_trace(ostringstream& os, pentry_header& pe)
{
  typedef void (*gen_payload_f)(ostringstream&, size_t);
  const gen_payload_f type_payloadgens[] = {
    gen_one_html, gen_one_js, gen_one_swf, gen_one_pdf
  };

  pe.ptype = htons(TYPE_HTTP_RESPONSE);
  pe.port = htons(80);

  payload_type pt = pick_payload_type();
  size_t approx_size = rng_range_geom(16384, 4096);

  ostringstream cs;
  type_payloadgens[pt](cs, approx_size);
  string const& content = cs.str();

  os <<
    "HTTP/1.1 200 OK\r\n"
    "Server: Apache\r\n"
    "Accept-Ranges: bytes\r\n"
    "Content-Type: " << type_mimes[pt] << "\r\n"
    "Content-Length: " << content.size() << "\r\n"
    "Connection: keep-alive\r\n\r\n" << content;
}

static void
gen_traces(unsigned long n, const char *fname,
           void (*gen_one)(ostringstream&, pentry_header&))
{
  FILE *fp = fopen(fname, "wb");
  if (!fp) {
    perror(fname);
    exit(1);
  }

  for (unsigned long i = 0; i < n; i++) {
    pentry_header pe;
    memset(&pe, 0, sizeof(pe));

    ostringstream os;
    gen_one(os, pe);

    string const& o = os.str();
    pe.length = htonl(o.size());
    if (fwrite(&pe, sizeof(pentry_header), 1, fp) != sizeof(pentry_header))
      log_warn("error writing data: %s", strerror(errno));

    if (fwrite(o.data(), o.size(), 1, fp)!= sizeof(pentry_header))
      log_warn("error writing data: %s", strerror(errno));

  }

  if (ferror(fp) || fclose(fp)) {
    perror(fname);
    exit(1);
  }
}

int
main()
{
  gen_traces(10000, "traces/client.out", gen_one_client_trace);
  gen_traces(10000, "traces/server.out", gen_one_server_trace);
}
