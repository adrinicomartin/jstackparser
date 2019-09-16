package jstackparser

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

const maxstackdepth = 20

//JavaThreadDump represents all the information parsed for the complete stacktrace
type JavaThreadDump struct {
	Date          string                 `json:"date"`
	VersionString string                 `json:"versionString"`
	ByStack       map[string]int         `json:"byStack"`
	ByStatus      map[string]int         `json:"byStatus"`
	LockOwners    map[string]string      `json:"lockOwners"`
	Threads       map[string]*JavaThread `json:"threads"`
	TotalThreads  int                    `json:"totalThreads"`
	Problems      []string               `json:"problems"`
}

func (jtd *JavaThreadDump) analyze() int {
	jtd.Problems = make([]string, 0)
	for tid, jt := range jtd.Threads {
		if jt.Status == "BLOCKED" {
			for _, lock := range jt.LocksWaiting {
				if jtd.LockOwners[lock] != "" {
					tname := jtd.Threads[jtd.LockOwners[lock]].Name
					problem := fmt.Sprintf("%s[%s] blocked for %s[%s]. lock %s", jt.Name, tid, jtd.LockOwners[lock], tname, lock)
					jtd.Problems = append(jtd.Problems, problem)
				}
			}
		}
		if jt.StackDepth > maxstackdepth && jt.Status != "RUNNABLE" {
			problem := fmt.Sprintf("%s[%s] waiting with stack depth %d.", jt.Name, tid, jt.StackDepth)
			jtd.Problems = append(jtd.Problems, problem)
		}
	}
	sort.Slice(jtd.Problems, func(i, j int) bool { return jtd.Problems[i] < jtd.Problems[j] })
	return len(jtd.Problems)
}

//ToJSON get the json string of JavaThreadDump struct.
func (jtd *JavaThreadDump) ToJSON() string {
	res2B, _ := json.Marshal(jtd)
	var prettyJSON bytes.Buffer
	json.Indent(&prettyJSON, res2B, "", "\t")
	return prettyJSON.String()
}

//JavaThread represents the information parsed for a single thread
type JavaThread struct {
	Name           string   `json:"name"`
	InternalNumber string   `json:"internalNumber"`
	IsDaemon       bool     `json:"isDaemon"`
	Status         string   `json:"status"`
	Prio           int      `json:"prio"`
	OSPrio         int      `json:"osPrio"`
	ThreadID       int64    `json:"threadId"`
	TID            string   `json:"tid"`
	NID            string   `json:"nid"`
	Stack          []string `json:"stack"`
	StackHash      string   `json:"stackHash"`
	StackDepth     int      `json:"stackDepth"`
	LocksOwned     []string `json:"locksOwned"`
	LocksWaiting   []string `json:"locksWaiting"`
}

func (jt *JavaThread) analyze() {
	h := sha256.New()
	depth := 0
	for _, stackLine := range jt.Stack {
		if strings.HasPrefix(stackLine, "\tat ") {
			depth++
			h.Write([]byte(stackLine))
		}
	}
	jt.StackHash = fmt.Sprintf("%x", h.Sum(nil))
	jt.StackDepth = depth
}

//ToJSON get the json string of JavaThread struct.
func (jt *JavaThread) ToJSON() string {
	jt.analyze()
	res2B, _ := json.Marshal(jt)
	var prettyJSON bytes.Buffer
	json.Indent(&prettyJSON, res2B, "", "\t")
	return prettyJSON.String()
}

func newJavaThread() *JavaThread {
	jt := new(JavaThread)
	jt.Stack = make([]string, 0)
	jt.LocksOwned = make([]string, 0)
	jt.LocksWaiting = make([]string, 0)
	return jt
}

//ParseJStack receives a jstack command output and parse it to extract the JavaThreadDump structure.
func ParseJStack(jstackStr string) (*JavaThreadDump, error) {
	lines := strings.Split(jstackStr, "\n")
	validVersion := false
	re, err := regexp.Compile("\"([^\"]+)\" (#[0-9]+)( daemon)? prio=([0-9]+)? os_prio=([0-9]+) tid=([a-z0-9]+) nid=([a-z0-9]+) ([^$]*)")
	if err != nil {
		return nil, err
	}
	reStatus, err := regexp.Compile("[ ]+java.lang.Thread.State: ([^ ]*)")
	if err != nil {
		return nil, err
	}
	reLock, err := regexp.Compile("[\t]+- locked <([^>]+)>")
	if err != nil {
		return nil, err
	}
	reWLock, err := regexp.Compile("[\t]+- waiting to lock <([^>]+)>")
	if err != nil {
		return nil, err
	}
	jtd := new(JavaThreadDump)

	currJT := newJavaThread()
	jts := make(map[string]*JavaThread)
	for i, line := range lines {
		if i == 0 {
			jtd.Date = line
		} else if strings.HasPrefix(line, "Full thread dump ") {
			validVersion = true
			jtd.VersionString = line[17:]
		} else if validVersion && strings.HasPrefix(line, "\"") {
			if currJT.Name != "" {
				currJT = newJavaThread()
			}
			res := re.FindStringSubmatch(line)
			if len(res) > 0 {
				currJT.Name = res[1]
				currJT.InternalNumber = res[2]
				currJT.IsDaemon = res[3] == " daemon"
				prio, _ := strconv.Atoi(res[4])
				currJT.Prio = prio
				osprio, _ := strconv.Atoi(res[5])
				currJT.OSPrio = osprio
				currJT.TID = res[6]
				currJT.NID = res[7]
				threadID, _ := strconv.ParseInt(res[7][2:], 16, 64)
				currJT.ThreadID = threadID
				currJT.Status = res[8]
				jts[currJT.TID] = currJT
			}
		} else if validVersion && strings.HasPrefix(line, "   java.lang.Thread.State:") {
			res := reStatus.FindStringSubmatch(line)
			if len(res) > 0 {
				currJT.Status = res[1]
			}
		} else if validVersion && strings.HasPrefix(line, "\t") {
			currJT.Stack = append(currJT.Stack, line)
			if strings.HasPrefix(line, "\t- locked ") {
				res := reLock.FindStringSubmatch(line)
				if len(res) > 0 {
					currJT.LocksOwned = append(currJT.LocksOwned, res[1])
				} else {
					log.Error("Failed to find lock ID. " + line)
				}
			} else if strings.HasPrefix(line, "\t- waiting to lock ") {
				res := reWLock.FindStringSubmatch(line)
				if len(res) > 0 {
					currJT.LocksWaiting = append(currJT.LocksWaiting, res[1])
				} else {
					log.Error("Failed to find wait lock ID. " + line)
				}
			}
		}
	}
	if !validVersion {
		return jtd, fmt.Errorf("couldn't find a valid java jstack output")
	}
	jtd.Threads = jts
	jtd.TotalThreads = len(jts)
	jtd.ByStatus = make(map[string]int)
	jtd.ByStack = make(map[string]int)
	jtd.LockOwners = make(map[string]string)
	jtd.Problems = make([]string, 0)
	for _, jt := range jtd.Threads {
		jt.analyze()
		jtd.ByStack[jt.StackHash]++
		jtd.ByStatus[jt.Status]++
		for _, lock := range jt.LocksOwned {
			jtd.LockOwners[lock] = jt.TID
		}
	}
	jtd.analyze()
	log.Debug("Finished parsing.")
	return jtd, nil
}
