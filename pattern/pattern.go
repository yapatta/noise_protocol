package pattern

const (
	TokenE Token = iota
	TokenS
	TokenEE
	TokenES
	TokenSE
	TokenSS
	TokenPSK
)

var (
	acceptedPatterns = map[string]*MessagePattern{}
)

type Message []Token

type Token uint8

type MessagePattern struct {
	name        string
	preMessages []Message
	messages    []Message
}

func FromString(name string) *MessagePattern {
	return acceptedPatterns[name]
}

func (p *MessagePattern) String() string {
	return p.name
}

func (p *MessagePattern) PreMessages() []Message {
	return p.preMessages
}

func (p *MessagePattern) Messages() []Message {
	return p.messages
}

var (
	// N is the N one-way handshake pattern.
	N = &MessagePattern{
		name: "N",
		preMessages: []Message{
			nil,
			{TokenS},
		},
		messages: []Message{
			{TokenE, TokenES},
		},
	}
	NN = &MessagePattern{
		name:        "NN",
		preMessages: []Message{},
		messages: []Message{
			{TokenE},
			{TokenE, TokenEE},
		},
	}
	XX = &MessagePattern{
		name:        "XX",
		preMessages: []Message{},
		messages: []Message{
			{TokenE},
			{TokenE, TokenEE, TokenS, TokenES},
			{TokenS, TokenSE},
		},
	}
	KN = &MessagePattern{
		name: "KN",
		preMessages: []Message{
			{TokenS},
		},
		messages: []Message{
			{TokenE},
			{TokenE, TokenEE, TokenSE},
		},
	}
	IX = &MessagePattern{
		name:        "IX",
		preMessages: []Message{},
		messages: []Message{
			{TokenE, TokenS},
			{TokenE, TokenEE, TokenSE, TokenS, TokenSE},
		},
	}
	NK1 = &MessagePattern{
		name: "NK1",
		preMessages: []Message{
			nil,
			{TokenS},
		},
		messages: []Message{
			{TokenE},
			{TokenE, TokenEE, TokenES},
		},
	}
	XKpsk3 = &MessagePattern{
		name: "XKpsk3",
		preMessages: []Message{
			nil,
			{TokenS},
		},
		messages: []Message{
			{TokenE, TokenES},
			{TokenE, TokenEE},
			{TokenS, TokenSE, TokenPSK},
		},
	}
)

func InitializePatterns() {
	for _, p := range []*MessagePattern{N, NN, XX, KN, IX, NK1, XKpsk3} {
		// TODO: check pattern's validity
		acceptedPatterns[p.String()] = p
	}
}
