package store

// ModuleID names a data-owning module, for example "ied", "telemetry" or
// "security".
type ModuleID string

// DatabaseID names one database on a node.
type DatabaseID string

// Database is one store with its single writer. Other modules read it only
// through interfaces the writer's module hands out (Outbox, CursorStore),
// never by opening the file.
type Database struct {
	ID      DatabaseID
	Writer  ModuleID
	Streams []StreamID
	Classes []StreamClass
	Quotas  []Quota
}

// Layout is every database on a node.
type Layout struct {
	Databases []Database
}

// Validate checks per-module data ownership:
//   - every database has an ID and exactly one writer;
//   - a stream belongs to exactly one database;
//   - every class a database holds has exactly one quota there;
//   - audit is never in a database with any other class, so a full audit
//     store cannot stop evidence collection and an evidence flood cannot
//     stop audit.
func (l Layout) Validate() error {
	dbs := map[DatabaseID]bool{}
	streams := map[StreamID]DatabaseID{}
	for _, d := range l.Databases {
		if d.ID == "" {
			return errf(CodeInvalid, nil, "database with no ID")
		}
		if dbs[d.ID] {
			return errf(CodeInvalid, nil, "database %s declared twice", d.ID)
		}
		dbs[d.ID] = true
		if d.Writer == "" {
			return errf(CodeInvalid, nil, "database %s has no writer", d.ID)
		}
		for _, s := range d.Streams {
			if s == "" {
				return errf(CodeInvalid, nil, "database %s: empty stream ID", d.ID)
			}
			if other, ok := streams[s]; ok {
				return errf(CodeInvalid, nil, "stream %s is in databases %s and %s", s, other, d.ID)
			}
			streams[s] = d.ID
		}
		if len(d.Classes) == 0 {
			return errf(CodeInvalid, nil, "database %s holds no class", d.ID)
		}
		classes := map[StreamClass]bool{}
		for _, c := range d.Classes {
			if _, err := ActionFor(c); err != nil {
				return err
			}
			classes[c] = true
		}
		if classes[ClassAudit] && len(classes) > 1 {
			return errf(CodeInvalid, nil, "database %s mixes audit with other classes", d.ID)
		}
		quotas := map[StreamClass]bool{}
		for _, q := range d.Quotas {
			if err := q.Validate(); err != nil {
				return err
			}
			if !classes[q.Class] {
				return errf(CodeInvalid, nil, "database %s: quota for class %s it does not hold", d.ID, q.Class)
			}
			if quotas[q.Class] {
				return errf(CodeInvalid, nil, "database %s: two quotas for %s", d.ID, q.Class)
			}
			quotas[q.Class] = true
		}
		for c := range classes {
			if !quotas[c] {
				return errf(CodeInvalid, nil, "database %s: no quota for %s", d.ID, c)
			}
		}
	}
	return nil
}
