package helpdesk

// Message is a fixed-text notice. No field comes from a technician and the body carries no link (C6;
// CISA AA23-320A: anti-vishing wording).
type Message struct {
	Subject string
	Body    string
}

// CodeMessage is the one message the help desk sends. The code is the only variable part.
func CodeMessage(code string) Message {
	return Message{
		Subject: "IT help desk verification code",
		Body: "The IT help desk is verifying a request made in your name. Your code is " + code + ". " +
			"Share it only with the person who asked for it, and only if you made the request. " +
			"It expires in 5 minutes. If you did not ask for help, ignore this message and tell your IT help desk.",
	}
}
