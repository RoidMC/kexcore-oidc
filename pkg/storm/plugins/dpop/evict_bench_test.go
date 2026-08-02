package dpop

import (
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// ─── 你贴的版本：锁外排序实现（仅用于 benchmark，不污染正式代码） ───

type benchEntry struct {
	key string
	t   time.Time
}

func (p *Plugin) evictBatchAlt() {
	const evictRatio = 4
	p.mu.Lock()
	snapshots := make([]benchEntry, 0, len(p.usedNonces))
	for jti, t := range p.usedNonces {
		snapshots = append(snapshots, benchEntry{jti, t})
	}
	p.mu.Unlock()

	target := len(snapshots) / evictRatio
	if target == 0 {
		return
	}
	slices.SortFunc(snapshots, func(a, b benchEntry) int {
		if a.t.Before(b.t) {
			return -1
		}
		if a.t.After(b.t) {
			return 1
		}
		return 0
	})
	cutoff := snapshots[target-1].t

	toDelete := make(map[string]struct{}, target)
	for i := 0; i < target; i++ {
		if !snapshots[i].t.After(cutoff) {
			toDelete[snapshots[i].key] = struct{}{}
		}
	}
	p.mu.Lock()
	for jti := range toDelete {
		delete(p.usedNonces, jti)
	}
	p.mu.Unlock()
}

// ─── 两个 hot-path 模拟：分别走"锁内排序"和"锁外排序" ───

// hotLocked 模拟磁盘版：持锁期间完成 收集+排序+删除。
func hotLocked(p *Plugin, id string) {
	p.mu.Lock()
	if _, exists := p.usedNonces[id]; exists {
		p.mu.Unlock()
		return
	}
	if len(p.usedNonces) >= maxNonceCacheSize {
		p.evictOldestLocked()
	}
	p.usedNonces[id] = time.Now()
	p.mu.Unlock()
}

// hotBatch 模拟你贴的版：先解锁，再在锁外排序回收。
func hotBatch(p *Plugin, id string) {
	needEvict := false
	p.mu.Lock()
	if _, exists := p.usedNonces[id]; exists {
		p.mu.Unlock()
		return
	}
	if len(p.usedNonces) >= maxNonceCacheSize {
		needEvict = true
	}
	p.usedNonces[id] = time.Now()
	p.mu.Unlock()

	if needEvict {
		p.evictBatchAlt()
	}
}

func prefill(p *Plugin) {
	base := time.Now()
	for i := 0; i < maxNonceCacheSize; i++ {
		p.usedNonces[string(rune(i))] = base.Add(-time.Duration(i) * time.Millisecond)
	}
}

// ─── 单线程 (无竞争) ───

func BenchmarkEvictLocked_Serial(b *testing.B) {
	p := &Plugin{usedNonces: make(map[string]time.Time, maxNonceCacheSize)}
	prefill(p)
	var counter int64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := string(rune(atomic.AddInt64(&counter, 1)))
		hotLocked(p, id)
	}
}

func BenchmarkEvictBatch_Serial(b *testing.B) {
	p := &Plugin{usedNonces: make(map[string]time.Time, maxNonceCacheSize)}
	prefill(p)
	var counter int64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := string(rune(atomic.AddInt64(&counter, 1)))
		hotBatch(p, id)
	}
}

// ─── 高并发 (RunParallel, 触发锁竞争) ───

func BenchmarkEvictLocked_Parallel(b *testing.B) {
	p := &Plugin{usedNonces: make(map[string]time.Time, maxNonceCacheSize)}
	prefill(p)
	var counter int64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			id := strconv.Itoa(int(atomic.AddInt64(&counter, 1)))
			hotLocked(p, id)
		}
	})
}

func BenchmarkEvictBatch_Parallel(b *testing.B) {
	p := &Plugin{usedNonces: make(map[string]time.Time, maxNonceCacheSize)}
	prefill(p)
	var counter int64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			id := strconv.Itoa(int(atomic.AddInt64(&counter, 1)))
			hotBatch(p, id)
		}
	})
}
