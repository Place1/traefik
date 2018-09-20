package acme

import (
	"encoding/json"
	"fmt"

	"github.com/containous/traefik/log"
	"github.com/containous/traefik/safe"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Kubernetes struct {
	Namespace string
}

type KubernetesStore struct {
	namespace    string
	storedData   *StoredData
	saveDataChan chan *StoredData
}

func NewKubernetesStore(namespace string) *KubernetesStore {
	store := &KubernetesStore{
		namespace:    namespace,
		saveDataChan: make(chan *StoredData),
		storedData: &StoredData{
			HTTPChallenges: make(map[string]map[string][]byte),
			TLSChallenges:  make(map[string]*Certificate),
		},
	}
	store.listenSaveAction()
	store.load()
	return store
}

func (k *KubernetesStore) GetAccount() (*Account, error) {
	return k.storedData.Account, nil
}

func (k *KubernetesStore) SaveAccount(account *Account) error {
	k.storedData.Account = account
	k.saveDataChan <- k.storedData
	return nil
}

func (k *KubernetesStore) GetCertificates() ([]*Certificate, error) {
	return k.storedData.Certificates, nil
}

func (k *KubernetesStore) SaveCertificates(certificates []*Certificate) error {
	k.storedData.Certificates = certificates
	k.saveDataChan <- k.storedData
	return nil
}

func (k *KubernetesStore) GetHTTPChallengeToken(token, domain string) ([]byte, error) {
	if _, ok := k.storedData.HTTPChallenges[token]; !ok {
		return nil, fmt.Errorf("cannot find challenge for token %v", token)
	}
	result, ok := k.storedData.HTTPChallenges[token][domain]
	if !ok {
		return nil, fmt.Errorf("cannot find challenge for token %v", token)
	}
	return result, nil
}

func (k *KubernetesStore) SetHTTPChallengeToken(token, domain string, keyAuth []byte) error {
	if _, ok := k.storedData.HTTPChallenges[token]; !ok {
		k.storedData.HTTPChallenges[token] = map[string][]byte{}
	}
	k.storedData.HTTPChallenges[token][domain] = keyAuth
	k.saveDataChan <- k.storedData
	return nil
}

func (k *KubernetesStore) RemoveHTTPChallengeToken(token, domain string) error {
	delete(k.storedData.HTTPChallenges[token], domain)
	k.saveDataChan <- k.storedData
	return nil
}

func (k *KubernetesStore) AddTLSChallenge(domain string, cert *Certificate) error {
	k.storedData.TLSChallenges[domain] = cert
	k.saveDataChan <- k.storedData
	return nil
}

func (k *KubernetesStore) GetTLSChallenge(domain string) (*Certificate, error) {
	return k.storedData.TLSChallenges[domain], nil
}

func (k *KubernetesStore) RemoveTLSChallenge(domain string) error {
	delete(k.storedData.TLSChallenges, domain)
	return nil
}

func (k *KubernetesStore) listenSaveAction() {
	safe.Go(func() {
		for object := range k.saveDataChan {
			err := k.store(object)
			if err != nil {
				log.Error(err)
			}
		}
	})
}

func (k *KubernetesStore) client() (*kubernetes.Clientset, error) {
	config, err := rest.InClusterConfig()
	config.TLSClientConfig.CAFile = ""
	config.Host = "http://localhost:8001"
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

func (k *KubernetesStore) exists() (bool, error) {
	clientset, err := k.client()
	if err != nil {
		log.Error(err)
		return false, err
	}
	_, err = clientset.CoreV1().Secrets(k.namespace).Get("traefik-acme-storage", metav1.GetOptions{})
	if err != nil {
		if err.(*errors.StatusError).ErrStatus.Reason == "NotFound" {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (k *KubernetesStore) load() error {
	clientset, err := k.client()
	if err != nil {
		log.Error(err)
		return err
	}
	secret, err := clientset.CoreV1().Secrets(k.namespace).Get("traefik-acme-storage", metav1.GetOptions{})
	if err != nil {
		log.Error(err)
		return err
	}
	data := secret.Data["acme"]
	json.Unmarshal(data, k.storedData)
	return nil
}

func (k *KubernetesStore) store(object *StoredData) error {
	data, err := json.MarshalIndent(object, "", "  ")
	if err != nil {
		return err
	}
	secret := &v1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "traefik-acme-storage",
			Namespace: k.namespace,
		},
		Type: "Opaque",
		Data: map[string][]byte{
			"acme": data,
		},
	}
	clientset, err := k.client()
	if err != nil {
		return err
	}
	exists, err := k.exists()
	if err != nil {
		log.Error(err)
		return err
	}
	if exists {
		_, err = clientset.CoreV1().Secrets(k.namespace).Update(secret)
	} else {
		_, err = clientset.CoreV1().Secrets(k.namespace).Create(secret)
	}
	if err != nil {
		return err
	}
	return err
}
