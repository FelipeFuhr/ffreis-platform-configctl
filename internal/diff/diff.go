package diff

import "github.com/ffreis/platform-configctl/internal/store"

const maskedValue = "<encrypted>"

// Differ compares live DynamoDB state to a reference snapshot.
type Differ struct{}

// New constructs a Differ.
func New() *Differ { return &Differ{} }

// Diff compares live items to snapshot items.
// Secret values are never exposed; they appear as "<encrypted>".
func (d *Differ) Diff(live, snapshot []*store.Item) *Result {
	liveMap := indexItems(live)
	snapMap := indexItems(snapshot)

	result := &Result{}

	// Items in snapshot.
	for key, snapItem := range snapMap {
		liveItem, exists := liveMap[key]
		if !exists {
			result.Added = append(result.Added, Change{
				Kind:     Added,
				Key:      snapItem.Key,
				ItemType: snapItem.Type,
				NewValue: safeValue(snapItem),
			})
			continue
		}
		if liveItem.Value != snapItem.Value {
			result.Modified = append(result.Modified, Change{
				Kind:     Modified,
				Key:      snapItem.Key,
				ItemType: snapItem.Type,
				OldValue: safeValue(liveItem),
				NewValue: safeValue(snapItem),
			})
		} else {
			result.Unchanged = append(result.Unchanged, Change{
				Kind:     Unchanged,
				Key:      snapItem.Key,
				ItemType: snapItem.Type,
				OldValue: safeValue(liveItem),
				NewValue: safeValue(snapItem),
			})
		}
	}

	// Items only in live (not in snapshot).
	for key, liveItem := range liveMap {
		if _, exists := snapMap[key]; !exists {
			result.Deleted = append(result.Deleted, Change{
				Kind:     Deleted,
				Key:      liveItem.Key,
				ItemType: liveItem.Type,
				OldValue: safeValue(liveItem),
			})
		}
	}

	return result
}

// indexItems builds a key→Item map using "type:key" as the map key to
// distinguish configs from secrets with the same name.
func indexItems(items []*store.Item) map[string]*store.Item {
	m := make(map[string]*store.Item, len(items))
	for _, it := range items {
		m[string(it.Type)+":"+it.Key] = it
	}
	return m
}

// safeValue returns the item value for configs and a placeholder for secrets.
func safeValue(item *store.Item) string {
	if item.Encrypted || item.Type == store.ItemTypeSecret {
		return maskedValue
	}
	return item.Value
}
