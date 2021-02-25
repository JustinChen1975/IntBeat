package beater

import (
	"fmt"
	"time"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"

	"github.com/JustinChen1975/intbeat/config"
)

// intbeat configuration.
type intbeat struct {
	done   chan struct{}
	config config.Config
	//client beat.Client
}

// New creates an instance of intbeat.
func New(b *beat.Beat, cfg *common.Config) (beat.Beater, error) {
	c := config.DefaultConfig
	if err := cfg.Unpack(&c); err != nil {
		return nil, fmt.Errorf("Error reading config file: %v", err)
	}

	bt := &intbeat{
		done:   make(chan struct{}),
		config: c,
	}
	return bt, nil
}

// Run starts intbeat.
func (bt *intbeat) Run(b *beat.Beat) error {
	logp.Info("intbeat is running! Hit CTRL-C to stop it.")

	var err error
	//bt.client, err = b.Publisher.Connect()
	//client, err := b.Publisher.Connect()
	//client1, err := b.Publisher.Connect()
	if err != nil {
		return err
	}

	ticker := time.NewTicker(bt.config.Period)
	counter := 1

	//var  endSignal chan struct{}
	endSignal := make(chan struct{},2)

	go capture(b,endSignal)

	for {
		select {
		case <-bt.done:
			endSignal <- struct{}{}
			return nil
		case <-ticker.C:
		}

		//event := beat.Event{
		//	Timestamp: time.Now(),
		//	Fields: common.MapStr{
		//		"type":    b.Info.Name,
		//		"counter": counter,
		//	},
		//}
		//client.Publish(event)
		//client1.Publish(event)
		//logp.Info("Event sent")
		counter++
	}
}

// Stop stops intbeat.
func (bt *intbeat) Stop() {
	//bt.client.Close()
	close(bt.done)
}

//// Run starts intbeat.
//func (bt *intbeat) Run1(b *beat.Beat) error {
//	logp.Info("intbeat is running! Hit CTRL-C to stop it.")
//
//	var err error
//	bt.client[0], err = b.Publisher.Connect()
//	if err != nil {
//		return err
//	}
//
//	ticker := time.NewTicker(bt.config.Period)
//	counter := 1
//	for {
//		select {
//		case <-bt.done:
//			return nil
//		case <-ticker.C:
//		}
//
//		event := beat.Event{
//			Timestamp: time.Now(),
//			Fields: common.MapStr{
//				"type":    b.Info.Name,
//				"counter": counter,
//			},
//		}
//		bt.client.Publish(event)
//		logp.Info("Event sent")
//		counter++
//	}
//}
