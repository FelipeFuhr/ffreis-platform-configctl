package store

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// DynamoClient is the subset of the DynamoDB API that DynamoStore uses.
// Using an interface enables unit-testing with a fake.
type DynamoClient interface {
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	Query(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	Scan(ctx context.Context, params *dynamodb.ScanInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error)
}

// DynamoStore is the DynamoDB-backed Store implementation.
type DynamoStore struct {
	client    DynamoClient
	tableName string
}

// NewDynamoStore constructs a DynamoStore.
func NewDynamoStore(client DynamoClient, tableName string) *DynamoStore {
	return &DynamoStore{client: client, tableName: tableName}
}

// dynamoRecord is the on-disk shape persisted to DynamoDB.
type dynamoRecord struct {
	PK        string `dynamodbav:"PK"`
	SK        string `dynamodbav:"SK"`
	Value     string `dynamodbav:"value"`
	ItemType  string `dynamodbav:"item_type"`
	Encrypted bool   `dynamodbav:"encrypted"`
	KeyID     string `dynamodbav:"key_id"`
	Version   int64  `dynamodbav:"version"`
	Checksum  string `dynamodbav:"checksum"`
	CreatedAt string `dynamodbav:"created_at"`
	UpdatedAt string `dynamodbav:"updated_at"`
	UpdatedBy string `dynamodbav:"updated_by"`
	Project   string `dynamodbav:"project"`
	Env       string `dynamodbav:"env"`
	Key       string `dynamodbav:"key"`
}

func recordFromItem(item *Item) dynamoRecord {
	now := time.Now().UTC()
	createdAt := item.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}
	return dynamoRecord{
		PK:        item.PK(),
		SK:        item.SK(),
		Value:     item.Value,
		ItemType:  string(item.Type),
		Encrypted: item.Encrypted,
		KeyID:     item.KeyID,
		Version:   item.Version + 1,
		Checksum:  checksum(item.Value),
		CreatedAt: createdAt.Format(time.RFC3339),
		UpdatedAt: now.Format(time.RFC3339),
		UpdatedBy: item.UpdatedBy,
		Project:   item.Project,
		Env:       item.Env,
		Key:       item.Key,
	}
}

func itemFromRecord(r dynamoRecord) (*Item, error) {
	createdAt, _ := time.Parse(time.RFC3339, r.CreatedAt)
	updatedAt, _ := time.Parse(time.RFC3339, r.UpdatedAt)
	return &Item{
		Project:   r.Project,
		Env:       r.Env,
		Key:       r.Key,
		Value:     r.Value,
		Type:      ItemType(r.ItemType),
		Encrypted: r.Encrypted,
		KeyID:     r.KeyID,
		Version:   r.Version,
		Checksum:  r.Checksum,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
		UpdatedBy: r.UpdatedBy,
	}, nil
}

func checksum(value string) string {
	h := sha256.Sum256([]byte(value))
	return fmt.Sprintf("sha256:%x", h)
}

func (s *DynamoStore) Get(ctx context.Context, project, env string, itemType ItemType, key string) (*Item, error) {
	pk := pkFor(project, env)
	sk := itemType.SKPrefix() + key

	out, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: pk},
			"SK": &types.AttributeValueMemberS{Value: sk},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("dynamodb GetItem: %w", err)
	}
	if len(out.Item) == 0 {
		return nil, ErrNotFound
	}

	var rec dynamoRecord
	if err := attributevalue.UnmarshalMap(out.Item, &rec); err != nil {
		return nil, fmt.Errorf("unmarshal record: %w", err)
	}
	return itemFromRecord(rec)
}

func (s *DynamoStore) Set(ctx context.Context, item *Item) error {
	rec := recordFromItem(item)

	av, err := attributevalue.MarshalMap(rec)
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(s.tableName),
		Item:      av,
	}

	if item.Version == 0 {
		// New item: must not already exist.
		input.ConditionExpression = aws.String("attribute_not_exists(PK)")
	} else {
		// Update: current version must match.
		input.ConditionExpression = aws.String("#v = :expected")
		input.ExpressionAttributeNames = map[string]string{"#v": "version"}
		input.ExpressionAttributeValues = map[string]types.AttributeValue{
			":expected": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", item.Version)},
		}
	}

	_, err = s.client.PutItem(ctx, input)
	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if isConditionFailed(err, &condErr) {
			return &ErrVersionConflict{
				Key:             item.Key,
				ExpectedVersion: item.Version,
			}
		}
		return fmt.Errorf("dynamodb PutItem: %w", err)
	}
	return nil
}

func (s *DynamoStore) List(ctx context.Context, project, env string, itemType ItemType) ([]*Item, error) {
	pk := pkFor(project, env)
	prefix := itemType.SKPrefix()

	out, err := s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(s.tableName),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :prefix)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":     &types.AttributeValueMemberS{Value: pk},
			":prefix": &types.AttributeValueMemberS{Value: prefix},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("dynamodb Query: %w", err)
	}

	items := make([]*Item, 0, len(out.Items))
	for _, av := range out.Items {
		var rec dynamoRecord
		if err := attributevalue.UnmarshalMap(av, &rec); err != nil {
			return nil, fmt.Errorf("unmarshal record: %w", err)
		}
		item, err := itemFromRecord(rec)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

func (s *DynamoStore) Delete(ctx context.Context, project, env string, itemType ItemType, key string) error {
	pk := pkFor(project, env)
	sk := itemType.SKPrefix() + key

	_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: pk},
			"SK": &types.AttributeValueMemberS{Value: sk},
		},
	})
	if err != nil {
		return fmt.Errorf("dynamodb DeleteItem: %w", err)
	}
	return nil
}

func (s *DynamoStore) ListProjects(ctx context.Context) ([]string, error) {
	out, err := s.client.Scan(ctx, &dynamodb.ScanInput{
		TableName:            aws.String(s.tableName),
		ProjectionExpression: aws.String("project"),
	})
	if err != nil {
		return nil, fmt.Errorf("dynamodb Scan: %w", err)
	}

	seen := make(map[string]struct{})
	for _, av := range out.Items {
		if v, ok := av["project"]; ok {
			if s, ok := v.(*types.AttributeValueMemberS); ok {
				seen[s.Value] = struct{}{}
			}
		}
	}

	projects := make([]string, 0, len(seen))
	for p := range seen {
		projects = append(projects, p)
	}
	return projects, nil
}

// isConditionFailed checks whether err is a ConditionalCheckFailedException.
func isConditionFailed(err error, target **types.ConditionalCheckFailedException) bool {
	_ = target
	return strings.Contains(err.Error(), "ConditionalCheckFailedException")
}
