package bitwarden

import (
	"encoding/json"
	"log"
	"testing"
	"time"
)

func TestDateTime(t *testing.T) {
	layout := "2006-01-02T15:04:05.000Z"
	str := "2014-11-12T11:45:26.370Z"
	var tme Time
	var tmu Time
	tm, err := time.Parse(layout, str)
	tme.Time = tm

	if err != nil {
		t.Fatal(err)
	}

	s, err := tm.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	log.Println(string(s))

	err = tmu.UnmarshalJSON(s)
	if err != nil {
		t.Fatal(err)
	}
	log.Println(tm)
	if tme != tmu {
		t.Fatalf("Decoded time %s doesn't match orginal time %s", tmu, tme)
	}
}

func TestDateTimeUnmarshalJSON(t *testing.T) {
	s := []byte(`"2017-12-02T23:11:21.6"`)
	var tm Time

	err := tm.UnmarshalJSON(s)
	if err != nil {
		t.Fatal(err)
	}
	log.Println(tm)

	sd, err := tm.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	log.Println(string(sd))

	if string(sd) != string(s) {
		t.Fatalf("Decoded time %s doesn't match orginal time %s", sd, s)
	}
}

type myTimeStruct struct {
	Test string
	Time Time
}

func TestDateTimeJSON(t *testing.T) {
	var tme myTimeStruct
	jsonTime := []byte(`{"Test":"bla","Time":"2017-11-30T17:18:34.031234"}`)

	err := json.Unmarshal(jsonTime, &tme)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(tme)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != string(jsonTime) {
		t.Fatalf("Decoded time %s doesn't match orginal time %s", b, jsonTime)
	}

}
