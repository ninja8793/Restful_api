from .serializers import *
from rest_framework import generics,status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import *
import pdb

class Get_users(generics.GenericAPIView):
    serializer_class = NewUserSerializer
    queryset = ''
    permission_classes = (IsAuthenticated,)
    def get(self,request):
        obj = new_user.objects.filter(softdelete=False).all()
        serializer = GetUserSerializer(obj,many=True)

        ### Sessions store
        num_visits = request.session.get('num_visits', 1)
        request.session['num_visits'] = num_visits + 1
        print("You have visited this API >>>",num_visits)
        return Response(data=serializer.data, status=status.HTTP_200_OK)

class User_Crud(generics.GenericAPIView):
    serializer_class = NewUserSerializer
    queryset = ''
    permission_classes = (IsAuthenticated,)
    def get(self,request,pk):
        try:
            obj = new_user.objects.filter(pk=pk,softdelete=False).get()
            serializer = GetUserSerializer(obj)
            return Response(data=serializer.data, status=status.HTTP_200_OK)
        except:
            return Response('OOPS User Not Found.', status=status.HTTP_404_NOT_FOUND)

    def put(self, request, pk):
        try:
            obj = new_user.objects.filter(pk=pk,softdelete=False).get()
            serializer = UpdateUserSerializer(instance=obj,data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
        except:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        try:
            obj = new_user.objects.get(pk=pk)
            # obj.softdelete = True
            # obj.save()
            obj.delete()
            return Response('User Deleted Successfully .....!!',status=status.HTTP_200_OK)
        except:
            return Response('OOPS User Not Found.', status=status.HTTP_404_NOT_FOUND)

class Add_User(generics.GenericAPIView):
    serializer_class = NewUserSerializer
    queryset = ''
    permission_classes = (IsAuthenticated,)

    def post(self,request):
        serializer = NewUserSerializer(data=request.data)
        if serializer.is_valid():
            password = make_password(request.data['password'])
            serializer.save(password = password)
            # serializer.save()
            return Response(data=serializer.data,status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)