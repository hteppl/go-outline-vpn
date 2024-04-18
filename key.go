package main

type OutlineKey struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Password  string `json:"password"`
	Port      int64  `json:"port"`
	Method    string `json:"method"`
	AccessURL string `json:"accessUrl"`
}

type KeyBuilder interface {
	SetID(id string) KeyBuilder
	SetName(name string) KeyBuilder
	SetPassword(password string) KeyBuilder
	SetPort(port int64) KeyBuilder
	SetMethod(method string) KeyBuilder
	Build() *OutlineKey
}

type keyBuilder struct {
	key *OutlineKey
}

type BytesTransferred struct {
	BytesTransferredByUserId map[string]int64 `json:"bytesTransferredByUserId"`
}

func NewKeyBuilder() KeyBuilder {
	return &keyBuilder{
		key: &OutlineKey{},
	}
}

func (k *keyBuilder) SetID(id string) KeyBuilder {
	k.key.ID = id
	return k
}

func (k *keyBuilder) SetName(name string) KeyBuilder {
	k.key.Name = name
	return k
}

func (k *keyBuilder) SetPassword(password string) KeyBuilder {
	k.key.Password = password
	return k
}

func (k *keyBuilder) SetPort(port int64) KeyBuilder {
	k.key.Port = port
	return k
}

func (k *keyBuilder) SetMethod(method string) KeyBuilder {
	k.key.Method = method
	return k
}

func (k *keyBuilder) Build() *OutlineKey {
	return k.key
}
