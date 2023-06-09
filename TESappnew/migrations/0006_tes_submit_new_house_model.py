# Generated by Django 4.1.5 on 2023-03-03 06:29

from django.db import migrations, models
import djongo.models.fields


class Migration(migrations.Migration):

    dependencies = [
        ('TESappnew', '0005_alter_tes_file_upload_model_file'),
    ]

    operations = [
        migrations.CreateModel(
            name='TES_submit_new_house_model',
            fields=[
                ('id', djongo.models.fields.ObjectIdField(auto_created=True, db_column='_id', primary_key=True, serialize=False)),
                ('house_id', models.EmailField(max_length=100)),
                ('addr1', models.CharField(max_length=100)),
                ('addr2', models.CharField(max_length=100)),
                ('customer_name', models.CharField(max_length=100)),
                ('phone', models.CharField(max_length=100)),
                ('email', models.CharField(max_length=100)),
            ],
            options={
                'verbose_name_plural': 'new_house',
                'db_table': 'new_house',
            },
        ),
    ]
