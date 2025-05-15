как Поднять через minikube start

eval $(minikube docker-env)
docker build -t test-app:latest .
kubectl apply -f k8s/pod.yml
kubectl port-forward pod/app 5000:5000
kubectl apply -f k8s/pod.yml
kubectl port-forward pod/app 30000:5000