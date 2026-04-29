from transformers import pipeline


classifier = None

def load_bert():
    global classifier
    classifier = pipeline("text-classification", model="./bert_model")

def bert_predict(url):
    global classifier
    if classifier is None:
        load_bert()

    result = classifier(url)[0]

    label = result['label']
    score = result['score']

    if label == "LABEL_1":
        return "phishing", score
    else:
        return "legitimate", score