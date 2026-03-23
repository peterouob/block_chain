package chain

import (
	"errors"
	"sync"
)

type ObjectStorer interface {
	Get(id ObjectId) (Object, error)
	Put(object Object) error
	Delete(id ObjectId) error
	GetByOwner(address Address) ([]Object, error)
	Exists(id ObjectId) bool
}

type InMemStore struct {
	objects       map[ObjectId]Object
	reverseObject map[Address]map[ObjectId]struct{}
	ru            sync.RWMutex
}

func NewInMemStore() *InMemStore {
	return &InMemStore{
		objects:       make(map[ObjectId]Object),
		reverseObject: make(map[Address]map[ObjectId]struct{}),
	}
}

var ErrObjectNotFound = errors.New("object not found")

func (s *InMemStore) Get(id ObjectId) (Object, error) {
	s.ru.RLock()
	object, ok := s.objects[id]
	s.ru.RUnlock()
	if !ok {
		return object, ErrObjectNotFound
	}
	return object, nil
}

func (s *InMemStore) Put(object Object) error {
	objId := object.GetObjectID()
	s.ru.Lock()
	defer s.ru.Unlock()

	if o, ok := s.objects[objId]; ok {
		if _, ok := o.owner.(*AddressOwner); ok {
			delete(s.reverseObject[o.owner.(*AddressOwner).Address], objId)
			if len(s.reverseObject[o.owner.(*AddressOwner).Address]) == 0 {
				delete(s.reverseObject, o.owner.(*AddressOwner).Address)
			}
		}
	}

	switch object.owner.(type) {
	case *AddressOwner:
		newAddr := object.owner.(*AddressOwner).Address
		if s.reverseObject[newAddr] == nil {
			s.reverseObject[newAddr] = make(map[ObjectId]struct{})
		}
		s.reverseObject[newAddr][objId] = struct{}{}
	default:
	}
	s.objects[objId] = object
	return nil
}

func (s *InMemStore) Delete(id ObjectId) error {
	s.ru.Lock()
	defer s.ru.Unlock()

	if o, ok := s.objects[id]; ok {
		if _, ok := o.owner.(*AddressOwner); ok {
			delete(s.reverseObject[o.owner.(*AddressOwner).Address], id)

			if len(s.reverseObject[o.owner.(*AddressOwner).Address]) == 0 {
				delete(s.reverseObject, o.owner.(*AddressOwner).Address)
			}
		}
	}

	delete(s.objects, id)
	return nil
}

func (s *InMemStore) GetByOwner(address Address) ([]Object, error) {
	var objects []Object
	s.ru.RLock()
	defer s.ru.RUnlock()
	for id := range s.reverseObject[address] {
		objects = append(objects, s.objects[id])
	}
	return objects, nil
}

func (s *InMemStore) Exists(id ObjectId) bool {
	s.ru.RLock()
	defer s.ru.RUnlock()
	_, ok := s.objects[id]
	return ok
}
