import pandas as pd
from datasets import Dataset
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification, Trainer, TrainingArguments


df = pd.read_csv("final_dataset.csv")


dataset = Dataset.from_pandas(df[['url','label']])


tokenizer = DistilBertTokenizerFast.from_pretrained('distilbert-base-uncased')

def tokenize(example):
    return tokenizer(example['url'], truncation=True, padding='max_length')

dataset = dataset.map(tokenize, batched=True)

dataset = dataset.train_test_split(test_size=0.2)


model = DistilBertForSequenceClassification.from_pretrained('distilbert-base-uncased', num_labels=2)


training_args = TrainingArguments(
    output_dir='./results',
    num_train_epochs=2,
    per_device_train_batch_size=8,
    logging_dir='./logs'
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=dataset['train'],
    eval_dataset=dataset['test']
)


trainer.train()

model.save_pretrained("./bert_model")
tokenizer.save_pretrained("./bert_model")

print("BERT model trained and saved.")